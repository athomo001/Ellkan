// Autor: Athan Espinoza

//! Entrega de un secreto al lanzador de «Conectar» por una tubería con nombre
//! (named pipe) de un solo uso.
//!
//! Por qué no una variable de entorno: con Windows Terminal (`wt -w ellkan
//! new-tab ...`) la pestaña nueva la crea el proceso de Windows Terminal que ya
//! estaba abierto, no esta app, así que el entorno de esta app no llega al
//! `ssh`/`psql` de la pestaña. En cambio la tubería no depende de quién cree
//! el proceso: el lanzador (`ellkan_askpass.exe --lanzar`) la lee, arma el
//! entorno y recién ahí ejecuta el cliente.
//!
//! Protecciones:
//! - Nombre aleatorio de 128 bits, sin clientes remotos
//!   (`PIPE_REJECT_REMOTE_CLIENTS`) y una sola instancia
//!   (`FILE_FLAG_FIRST_PIPE_INSTANCE`: nadie puede crearla antes con ese nombre).
//! - ACL sólo para el dueño (SDDL `D:P(A;;GA;;;OW)`): otro usuario de la misma
//!   PC no puede abrirla.
//! - Sólo se entrega el secreto si el proceso que se conectó es el lanzador
//!   esperado (ruta de su ejecutable); cualquier otro cliente se desconecta.
//! - Se entrega una sola vez y la tubería vence a los `VIGENCIA`: si el
//!   lanzador nunca llega (la terminal no abrió), el secreto se descarta.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, LocalFree, ERROR_PIPE_CONNECTED, HANDLE, HLOCAL, INVALID_HANDLE_VALUE};
use windows::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
use windows::Win32::Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::Storage::FileSystem::{
  CreateFileW, FlushFileBuffers, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_GENERIC_READ, FILE_SHARE_NONE, OPEN_EXISTING,
  PIPE_ACCESS_OUTBOUND, FILE_FLAGS_AND_ATTRIBUTES,
};
use windows::Win32::System::Pipes::{
  ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
  PIPE_WAIT,
};
use windows::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION};
use zeroize::Zeroizing;

/// Cuánto espera la tubería a que el lanzador se conecte.
pub const VIGENCIA: Duration = Duration::from_secs(60);

/// Ruta completa de una tubería a partir de su nombre corto.
pub fn ruta_de(nombre: &str) -> String {
  format!(r"\\.\pipe\{nombre}")
}

fn a_utf16(texto: &str) -> Vec<u16> {
  texto.encode_utf16().chain(std::iter::once(0)).collect()
}

pub(crate) fn nombre_aleatorio() -> Result<String, String> {
  let mut bytes = [0u8; 16];
  // SAFETY: el buffer es válido y su largo lo da el slice.
  unsafe { BCryptGenRandom(None, &mut bytes, BCRYPT_USE_SYSTEM_PREFERRED_RNG) }
    .ok()
    .map_err(|e| format!("no se pudo generar el nombre de la tubería: {e}"))?;
  Ok(format!("ellkan-conectar-{}", bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()))
}

/// Ruta del ejecutable del proceso `pid`.
pub(crate) fn ejecutable_de(pid: u32) -> Option<PathBuf> {
  // SAFETY: handle propio, se cierra antes de salir.
  let proceso = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
  let mut buffer = [0u16; 1024];
  let mut largo = buffer.len() as u32;
  // SAFETY: `largo` indica el tamaño del buffer; la API lo actualiza con lo escrito.
  let ok = unsafe { QueryFullProcessImageNameW(proceso, PROCESS_NAME_WIN32, PWSTR(buffer.as_mut_ptr()), &mut largo) }.is_ok();
  // SAFETY: el handle es válido y no se usa después.
  let _ = unsafe { CloseHandle(proceso) };
  ok.then(|| PathBuf::from(String::from_utf16_lossy(&buffer[..largo as usize])))
}

/// Compara dos rutas de ejecutable ignorando mayúsculas y resolviendo enlaces.
pub(crate) fn misma_ruta(a: &Path, b: &Path) -> bool {
  match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
    (Ok(a), Ok(b)) => a.to_string_lossy().eq_ignore_ascii_case(&b.to_string_lossy()),
    _ => false,
  }
}

/// Handle de la tubería que se cierra solo.
struct Tuberia(HANDLE);

impl Drop for Tuberia {
  fn drop(&mut self) {
    // SAFETY: el handle es propio y no se usa después del drop.
    let _ = unsafe { CloseHandle(self.0) };
  }
}

// SAFETY: un HANDLE de tubería se puede usar desde otro hilo; sólo lo usa el
// hilo que atiende la conexión.
unsafe impl Send for Tuberia {}

fn crear_tuberia(ruta: &str) -> Result<Tuberia, String> {
  // Descriptor de seguridad: acceso total sólo para el dueño (quien la crea).
  let sddl = a_utf16("D:P(A;;GA;;;OW)");
  let mut descriptor = PSECURITY_DESCRIPTOR::default();
  // SAFETY: SDDL terminado en 0; el descriptor lo libera `LocalFree` más abajo.
  unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(sddl.as_ptr()), SDDL_REVISION_1, &mut descriptor, None) }
    .map_err(|e| format!("no se pudo preparar la tubería: {e}"))?;
  let atributos = SECURITY_ATTRIBUTES {
    nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
    lpSecurityDescriptor: descriptor.0,
    bInheritHandle: false.into(),
  };
  let nombre = a_utf16(ruta);
  // SAFETY: nombre terminado en 0 y atributos válidos durante la llamada.
  let handle = unsafe {
    CreateNamedPipeW(
      PCWSTR(nombre.as_ptr()),
      PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE,
      PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
      1,
      4096,
      0,
      0,
      Some(&atributos),
    )
  };
  // SAFETY: el descriptor salió de `ConvertString...` y ya no se usa.
  unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
  if handle == INVALID_HANDLE_VALUE {
    return Err(format!("no se pudo crear la tubería: {}", windows::core::Error::from_win32()));
  }
  Ok(Tuberia(handle))
}

/// Atiende conexiones hasta entregar el secreto al lanzador o hasta vencer.
fn atender(tuberia: Tuberia, secreto: Zeroizing<String>, lanzador: PathBuf, vence: Instant, servido: Arc<AtomicBool>) {
  loop {
    // SAFETY: handle válido; sin OVERLAPPED la llamada bloquea hasta que
    // alguien se conecta (o ya estaba conectado: ERROR_PIPE_CONNECTED).
    let conectado = match unsafe { ConnectNamedPipe(tuberia.0, None) } {
      Ok(()) => true,
      Err(e) => e.code() == ERROR_PIPE_CONNECTED.to_hresult(),
    };
    if !conectado || Instant::now() >= vence {
      break;
    }
    let mut pid = 0u32;
    // SAFETY: handle conectado y puntero a un u32 propio.
    let es_el_lanzador = unsafe { GetNamedPipeClientProcessId(tuberia.0, &mut pid) }.is_ok()
      && ejecutable_de(pid).is_some_and(|ruta| misma_ruta(&ruta, &lanzador));
    if es_el_lanzador {
      let mut escritos = 0u32;
      // SAFETY: buffer válido durante la llamada.
      let _ = unsafe { WriteFile(tuberia.0, Some(secreto.as_bytes()), Some(&mut escritos), None) };
      // Espera a que el lanzador lo lea. Después se cierra el handle (al salir
      // del bucle) en vez de `DisconnectNamedPipe`: así el lanzador ve fin de
      // datos y no un error de tubería desconectada.
      // SAFETY: handle válido.
      let _ = unsafe { FlushFileBuffers(tuberia.0) };
      servido.store(true, Ordering::SeqCst);
      break;
    }
    log::warn!("conectar: un proceso que no es el lanzador (pid {pid}) abrió la tubería del secreto; se ignoró");
    // SAFETY: handle válido.
    let _ = unsafe { DisconnectNamedPipe(tuberia.0) };
  }
  // `secreto` (Zeroizing) se borra de memoria al salir de acá.
}

/// Publica `secreto` en una tubería nueva que sólo `lanzador` puede leer, una
/// vez y dentro de `VIGENCIA`. Devuelve el nombre corto de la tubería (lo que
/// recibe `ellkan_askpass.exe --lanzar`).
pub fn servir_secreto_una_vez(secreto: Zeroizing<String>, lanzador: &Path) -> Result<String, String> {
  let nombre = nombre_aleatorio()?;
  let ruta = ruta_de(&nombre);
  let tuberia = crear_tuberia(&ruta)?;
  let vence = Instant::now() + VIGENCIA;
  let servido = Arc::new(AtomicBool::new(false));
  let lanzador = lanzador.to_path_buf();

  {
    let servido = servido.clone();
    std::thread::spawn(move || atender(tuberia, secreto, lanzador, vence, servido));
  }

  // Si nadie se conecta, `ConnectNamedPipe` bloquearía para siempre: al vencer
  // se conecta este mismo proceso (que no es el lanzador) para destrabarlo, y
  // el hilo ve que ya venció y termina descartando el secreto.
  {
    let ruta = ruta.clone();
    std::thread::spawn(move || {
      std::thread::sleep(VIGENCIA);
      if !servido.load(Ordering::SeqCst) {
        let ruta = a_utf16(&ruta);
        // SAFETY: nombre terminado en 0; el handle se cierra enseguida.
        if let Ok(h) = unsafe {
          CreateFileW(PCWSTR(ruta.as_ptr()), FILE_GENERIC_READ.0, FILE_SHARE_NONE, None, OPEN_EXISTING, FILE_FLAGS_AND_ATTRIBUTES(0), None)
        } {
          let _ = unsafe { CloseHandle(h) };
        }
      }
    });
  }

  Ok(nombre)
}
