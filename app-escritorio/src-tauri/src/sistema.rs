// Autor: Athan Espinoza

//! Integración con Windows: iniciar con la sesión (F-54), registrar el
//! esquema `ellkan://` (deep links) y enterarse de que la pantalla se bloqueó
//! (F-52). Linux/macOS quedan fuera por ahora (pedido explícito del
//! usuario): allá estas funciones dicen que no están soportadas.
//!
//! Las claves de registro viven en `HKEY_CURRENT_USER` (nunca hace falta ser
//! administrador). `ELLKAN_REGISTRO_RAIZ` (por defecto `Software`) permite a
//! las pruebas automáticas escribir en otra rama en vez de tocar el registro
//! real del usuario.

pub const ARG_MINIMIZADO: &str = "--minimizado";

/// Lo que corre el desinstalador (MSI) antes de borrar los archivos: deshace lo
/// que la app dejó FUERA de su carpeta (inicio con Windows y esquema
/// `ellkan://`, ambos en `HKEY_CURRENT_USER`). No toca la bóveda ni la
/// configuración: son datos del usuario y sobreviven a una desinstalación.
pub const ARG_LIMPIAR: &str = "--limpiar-sistema";

pub fn limpiar() {
  // Cada paso es independiente y ninguno debe frenar la desinstalación.
  let _ = configurar_autostart(false);
  let _ = configurar_enlaces(false);
}

/// Junto con `ARG_LIMPIAR`: además borra los datos del usuario (bóveda, ajustes,
/// copias de seguridad, datos de la ventana y claves del llavero). Sin esto, una
/// desinstalación los conserva a propósito: son la única copia de sus contraseñas.
pub const ARG_BORRAR_DATOS: &str = "--borrar-datos";

/// Como `ARG_BORRAR_DATOS`, pero le pregunta al usuario (dos veces, con «No» por
/// defecto). Es lo que usa el desinstalador cuando tiene interfaz.
pub const ARG_PREGUNTAR_DATOS: &str = "--preguntar-datos";

/// Carpetas que esta app crea con datos del usuario: `borrar_carpeta_de_datos`
/// sólo acepta borrar una con uno de estos nombres.
const CARPETAS_PROPIAS: &[&str] = &["Ellkan", "ellkan-datos", "com.ellkan.desktop"];

/// Borra `ruta` entera si es una carpeta de datos propia. Nunca borra otra cosa:
/// el nombre tiene que ser uno de `CARPETAS_PROPIAS` y la ruta no puede ser una
/// raíz ni una carpeta a menos de tres niveles de ella (una variable de entorno rara no puede
/// convertir esto en un `rm -rf` de algo ajeno). Reintenta unas veces porque
/// los procesos de WebView2 tardan un instante en soltar sus archivos.
pub fn borrar_carpeta_de_datos(ruta: &std::path::Path) -> Result<(), String> {
  let nombre = ruta.file_name().and_then(|n| n.to_str()).unwrap_or("");
  if !CARPETAS_PROPIAS.iter().any(|propia| propia.eq_ignore_ascii_case(nombre)) || ruta.components().filter(|c| matches!(c, std::path::Component::Normal(_))).count() < 3 {
    return Err(format!("se rechazó borrar {}: no es una carpeta de datos de Ellkan", ruta.display()));
  }
  if !ruta.exists() {
    return Ok(());
  }
  let mut ultimo = String::new();
  for _ in 0..6 {
    match std::fs::remove_dir_all(ruta) {
      Ok(()) => return Ok(()),
      Err(e) => {
        ultimo = e.to_string();
        std::thread::sleep(std::time::Duration::from_millis(500));
      }
    }
  }
  Err(format!("no se pudo borrar {}: {ultimo}", ruta.display()))
}

#[cfg(windows)]
mod windows_impl {
  use super::ARG_MINIMIZADO;
  use std::os::windows::process::CommandExt;
  use std::process::Command;

  const NOMBRE_RUN: &str = "Ellkan";
  /// `CREATE_NO_WINDOW`: que `reg.exe` no abra una consola.
  const SIN_VENTANA: u32 = 0x0800_0000;

  fn raiz() -> String {
    std::env::var("ELLKAN_REGISTRO_RAIZ").unwrap_or_else(|_| "Software".to_string())
  }
  fn clave_run() -> String {
    format!(r"HKCU\{}\Microsoft\Windows\CurrentVersion\Run", raiz())
  }
  fn clave_esquema() -> String {
    format!(r"HKCU\{}\Classes\{}", raiz(), ellkan_backend::desktop::enlaces::ESQUEMA)
  }

  fn reg(args: &[&str]) -> Result<String, String> {
    let salida = Command::new("reg")
      .args(args)
      .creation_flags(SIN_VENTANA)
      .output()
      .map_err(|e| format!("no se pudo ejecutar reg.exe: {e}"))?;
    if salida.status.success() {
      Ok(String::from_utf8_lossy(&salida.stdout).into_owned())
    } else {
      Err(String::from_utf8_lossy(&salida.stderr).trim().to_string())
    }
  }

  /// Línea que Windows ejecuta al iniciar sesión: este mismo `.exe`, en la
  /// bandeja (sin abrir la ventana), y con `--portable` si corre así.
  pub fn comando_de_inicio() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    let mut comando = format!("\"{}\" {ARG_MINIMIZADO}", exe.display());
    if crate::portable::activo() {
      comando.push(' ');
      comando.push_str(crate::portable::BANDERA);
    }
    Some(comando)
  }

  /// ¿Está activado el inicio con la sesión PARA ESTE `.exe`? Si la clave
  /// apunta a otra ruta (la app se movió de carpeta) cuenta como no activado:
  /// hay que volver a activarlo para que apunte a la ruta actual.
  pub fn autostart_activo() -> bool {
    let (Some(comando), Ok(salida)) = (comando_de_inicio(), reg(&["query", &clave_run(), "/v", NOMBRE_RUN])) else {
      return false;
    };
    salida.to_lowercase().contains(&comando.to_lowercase())
  }

  pub fn configurar_autostart(activo: bool) -> Result<(), String> {
    if activo {
      let comando = comando_de_inicio().ok_or("no se pudo resolver la ruta del ejecutable")?;
      reg(&["add", &clave_run(), "/v", NOMBRE_RUN, "/t", "REG_SZ", "/d", &comando, "/f"]).map(|_| ())
    } else if reg(&["query", &clave_run(), "/v", NOMBRE_RUN]).is_ok() {
      reg(&["delete", &clave_run(), "/v", NOMBRE_RUN, "/f"]).map(|_| ())
    } else {
      Ok(())
    }
  }

  fn comando_de_enlace() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    let mut comando = format!("\"{}\"", exe.display());
    if crate::portable::activo() {
      comando.push(' ');
      comando.push_str(crate::portable::BANDERA);
    }
    comando.push_str(" \"%1\"");
    Some(comando)
  }

  pub fn enlaces_activos() -> bool {
    let (Some(comando), Ok(salida)) = (comando_de_enlace(), reg(&["query", &format!(r"{}\shell\open\command", clave_esquema()), "/ve"])) else {
      return false;
    };
    salida.to_lowercase().contains(&comando.to_lowercase())
  }

  pub fn configurar_enlaces(activo: bool) -> Result<(), String> {
    let clave = clave_esquema();
    if activo {
      let comando = comando_de_enlace().ok_or("no se pudo resolver la ruta del ejecutable")?;
      reg(&["add", &clave, "/ve", "/d", "URL:Ellkan", "/f"])?;
      reg(&["add", &clave, "/v", "URL Protocol", "/t", "REG_SZ", "/d", "", "/f"])?;
      reg(&["add", &format!(r"{clave}\shell\open\command"), "/ve", "/d", &comando, "/f"]).map(|_| ())
    } else if reg(&["query", &clave]).is_ok() {
      reg(&["delete", &clave, "/f"]).map(|_| ())
    } else {
      Ok(())
    }
  }

  /// Pregunta si además de desinstalar hay que borrar los datos. Dos avisos
  /// seguidos, los dos con «No» por defecto: la bóveda es la única copia de sus
  /// contraseñas y borrarla no se puede deshacer.
  pub fn preguntar_borrar_datos() -> bool {
    use windows::core::PCWSTR;
    use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, IDYES, MB_DEFBUTTON2, MB_ICONWARNING, MB_SETFOREGROUND, MB_TOPMOST, MB_YESNO};

    let titulo = a_utf16_nulo("Desinstalar Ellkan");
    let preguntar = |texto: &str| -> bool {
      let texto = a_utf16_nulo(texto);
      // SAFETY: los dos buffers terminan en nulo y viven durante la llamada.
      unsafe {
        MessageBoxW(None, PCWSTR(texto.as_ptr()), PCWSTR(titulo.as_ptr()), MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 | MB_SETFOREGROUND | MB_TOPMOST)
          == IDYES
      }
    };
    preguntar(
      "\u{BF}Quieres borrar tambi\u{E9}n tus datos de Ellkan en este equipo?\n\nSe eliminar\u{E1}n tu b\u{F3}veda (todas tus contrase\u{F1}as), tus ajustes y las copias de seguridad. No se puede deshacer.\n\nElige \u{AB}No\u{BB} para conservarlos: si vuelves a instalar Ellkan los encontrar\u{E1}s tal cual.",
    ) && preguntar(
      "\u{DA}ltima confirmaci\u{F3}n: se borrar\u{E1}n TODAS las contrase\u{F1}as guardadas en este equipo.\n\n\u{BF}Continuar?",
    )
  }

  /// Borra del llavero de Windows las claves de envoltura que la app guardó para
  /// el desbloqueo rápido (`vault_<id>`, servicio «Ellkan»). Devuelve cuántas.
  pub fn borrar_credenciales_llavero() -> usize {
    borrar_credenciales_con_prefijo("vault_")
  }

  /// Igual, pero sólo las que empiezan con `prefijo` (así las pruebas no tocan las claves reales).
  pub fn borrar_credenciales_con_prefijo(prefijo: &str) -> usize {
    use windows::core::PCWSTR;
    use windows::Win32::Security::Credentials::{CredDeleteW, CredEnumerateW, CredFree, CREDENTIALW, CRED_ENUMERATE_FLAGS, CRED_TYPE_GENERIC};

    let filtro = a_utf16_nulo(&format!("{prefijo}*"));
    let mut cantidad = 0u32;
    let mut lista: *mut *mut CREDENTIALW = std::ptr::null_mut();
    let mut borradas = 0;
    // SAFETY: la API deja en `lista` un arreglo propio de `cantidad` punteros que se
    // libera con `CredFree`; cada nombre se copia antes de borrar.
    unsafe {
      if CredEnumerateW(PCWSTR(filtro.as_ptr()), Some(CRED_ENUMERATE_FLAGS(0)), &mut cantidad, &mut lista).is_err() {
        return 0;
      }
      for i in 0..cantidad as usize {
        let credencial = &**lista.add(i);
        let objetivo = credencial.TargetName.to_string().unwrap_or_default();
        // El almacén guarda "<usuario>.<servicio>": sólo las de servicio Ellkan.
        if credencial.Type == CRED_TYPE_GENERIC && objetivo.ends_with(".Ellkan") {
          let objetivo_w = a_utf16_nulo(&objetivo);
          if CredDeleteW(PCWSTR(objetivo_w.as_ptr()), CRED_TYPE_GENERIC, None).is_ok() {
            borradas += 1;
          }
        }
      }
      CredFree(lista as *const _);
    }
    borradas
  }

  // ---- Escritorio remoto (RDP) ------------------------------------------
  //
  // `mstsc` no acepta la contraseña por argumento. Lo que sí hace es usar la
  // credencial `TERMSRV/<host>` del Administrador de credenciales de Windows
  // (lo que guarda `cmdkey /generic:TERMSRV/…`) — pero `cmdkey` la pondría en
  // la línea de comandos, visible para cualquier proceso. Acá se escribe con
  // la API directa, sin pasar por ningún argumento, y con persistencia de
  // SESIÓN: nunca se guarda en disco y se borra a los pocos segundos.

  /// Nombres de credencial que `mstsc` puede buscar para `host:puerto`.
  fn objetivos_rdp(host: &str, puerto: u16) -> Vec<String> {
    let mut objetivos = vec![format!("TERMSRV/{host}")];
    if puerto != 3389 {
      objetivos.push(format!("TERMSRV/{host}:{puerto}"));
    }
    objetivos
  }

  fn a_utf16_nulo(texto: &str) -> Vec<u16> {
    texto.encode_utf16().chain(std::iter::once(0)).collect()
  }

  pub fn guardar_credencial_rdp(host: &str, puerto: u16, usuario: &str, contrasena: &str) -> Result<(), String> {
    use windows::core::PWSTR;
    use windows::Win32::Security::Credentials::{CredWriteW, CREDENTIALW, CRED_PERSIST_SESSION, CRED_TYPE_GENERIC};

    // `cmdkey` guarda la contraseña como UTF-16 sin nulo final: mismo formato.
    let mut blob: Vec<u8> = contrasena.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut usuario_w = a_utf16_nulo(usuario);
    for objetivo in objetivos_rdp(host, puerto) {
      let mut objetivo_w = a_utf16_nulo(&objetivo);
      let credencial = CREDENTIALW {
        Type: CRED_TYPE_GENERIC,
        TargetName: PWSTR(objetivo_w.as_mut_ptr()),
        UserName: PWSTR(usuario_w.as_mut_ptr()),
        CredentialBlobSize: blob.len() as u32,
        CredentialBlob: blob.as_mut_ptr(),
        Persist: CRED_PERSIST_SESSION,
        ..Default::default()
      };
      // SAFETY: los punteros apuntan a buffers vivos hasta después de la llamada.
      unsafe { CredWriteW(&credencial, 0) }.map_err(|e| format!("no se pudo dejar la credencial de Escritorio remoto: {e}"))?;
    }
    blob.fill(0);
    Ok(())
  }

  /// Borra las credenciales que dejó `guardar_credencial_rdp` (si ya no están, no es un error).
  pub fn borrar_credencial_rdp(host: &str, puerto: u16) {
    use windows::core::PCWSTR;
    use windows::Win32::Security::Credentials::{CredDeleteW, CRED_TYPE_GENERIC};
    for objetivo in objetivos_rdp(host, puerto) {
      let objetivo_w = a_utf16_nulo(&objetivo);
      // SAFETY: `objetivo_w` termina en nulo y vive durante la llamada.
      let _ = unsafe { CredDeleteW(PCWSTR(objetivo_w.as_ptr()), CRED_TYPE_GENERIC, None) };
    }
  }

  /// Usuario y contraseña de la credencial `TERMSRV/<host>` (sólo para pruebas).
  #[cfg(test)]
  pub fn leer_credencial_rdp(host: &str) -> Option<(String, String)> {
    use windows::core::PCWSTR;
    use windows::Win32::Security::Credentials::{CredFree, CredReadW, CREDENTIALW, CRED_TYPE_GENERIC};
    let objetivo_w = a_utf16_nulo(&format!("TERMSRV/{host}"));
    let mut puntero: *mut CREDENTIALW = std::ptr::null_mut();
    // SAFETY: la API deja en `puntero` un buffer propio que se libera con `CredFree`.
    unsafe {
      CredReadW(PCWSTR(objetivo_w.as_ptr()), CRED_TYPE_GENERIC, None, &mut puntero).ok()?;
      let c = &*puntero;
      let usuario = c.UserName.to_string().ok()?;
      let bytes = std::slice::from_raw_parts(c.CredentialBlob, c.CredentialBlobSize as usize);
      let unidades: Vec<u16> = bytes.as_chunks::<2>().0.iter().map(|p| u16::from_le_bytes(*p)).collect();
      let contrasena = String::from_utf16(&unidades).ok()?;
      CredFree(puntero as *const _);
      Some((usuario, contrasena))
    }
  }

  /// Id del subclase (identifica el nuestro entre los de la ventana).
  const ID_SUBCLASE: usize = 0x00E1_1CA4;

  /// Ventana de la app cuyo mensaje de cambio de sesión ya se maneja.
  unsafe extern "system" fn subclase(
    hwnd: windows::Win32::Foundation::HWND,
    mensaje: u32,
    wparam: windows::Win32::Foundation::WPARAM,
    lparam: windows::Win32::Foundation::LPARAM,
    _id: usize,
    dato: usize,
  ) -> windows::Win32::Foundation::LRESULT {
    use windows::Win32::UI::WindowsAndMessaging::WTS_SESSION_LOCK;
    use windows::Win32::UI::Shell::DefSubclassProc;
    use windows::Win32::UI::WindowsAndMessaging::WM_WTSSESSION_CHANGE;

    if mensaje == WM_WTSSESSION_CHANGE && wparam.0 as u32 == WTS_SESSION_LOCK {
      // SAFETY: `dato` es el `Box<Callback>` que dejó `vigilar_bloqueo`, que
      // se filtra a propósito y vive lo mismo que la ventana.
      let al_bloquear = unsafe { &*(dato as *const Callback) };
      al_bloquear();
    }
    // SAFETY: reenvío estándar al siguiente procedimiento de la ventana.
    unsafe { DefSubclassProc(hwnd, mensaje, wparam, lparam) }
  }

  type Callback = Box<dyn Fn() + Send + Sync>;

  /// Pide a Windows que avise a `hwnd` cuando la sesión cambia de estado
  /// (bloqueo/desbloqueo de pantalla) y llama `al_bloquear` cada vez que se
  /// BLOQUEA. Es el mecanismo documentado (`WM_WTSSESSION_CHANGE`): sin
  /// consultas periódicas y sin depender de qué valor devuelva una consulta de
  /// estado (que en Windows 8+ no coincide con lo documentado).
  ///
  /// Hay que llamarla desde el hilo que creó la ventana (el principal).
  pub fn vigilar_bloqueo(hwnd: windows::Win32::Foundation::HWND, al_bloquear: impl Fn() + Send + Sync + 'static) -> Result<(), String> {
    use windows::Win32::System::RemoteDesktop::{WTSRegisterSessionNotification, NOTIFY_FOR_THIS_SESSION};
    use windows::Win32::UI::Shell::SetWindowSubclass;

    let dato = Box::into_raw(Box::new(Box::new(al_bloquear) as Callback)) as usize;
    // SAFETY: `hwnd` es la ventana viva de la app y se llama desde su hilo;
    // el puntero `dato` queda válido para siempre (se filtra a propósito).
    unsafe {
      WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION).map_err(|e| format!("no se pudo registrar el aviso de bloqueo de pantalla: {e}"))?;
      if !SetWindowSubclass(hwnd, Some(subclase), ID_SUBCLASE, dato).as_bool() {
        return Err("no se pudo enganchar el aviso de bloqueo de pantalla a la ventana".to_string());
      }
    }
    Ok(())
  }

  /// Simula que Windows avisó que la pantalla se bloqueó (sólo para pruebas:
  /// bloquear la pantalla de verdad sacaría al usuario de su sesión).
  pub fn simular_bloqueo(hwnd: windows::Win32::Foundation::HWND) {
    use windows::Win32::Foundation::{LPARAM, WPARAM};
    use windows::Win32::UI::WindowsAndMessaging::WTS_SESSION_LOCK;
    use windows::Win32::UI::WindowsAndMessaging::{SendMessageW, WM_WTSSESSION_CHANGE};
    // SAFETY: `hwnd` es la ventana viva de la app.
    unsafe {
      SendMessageW(hwnd, WM_WTSSESSION_CHANGE, Some(WPARAM(WTS_SESSION_LOCK as usize)), Some(LPARAM(0)));
    }
  }
}

#[cfg(windows)]
pub use windows_impl::{
  autostart_activo, borrar_credencial_rdp, borrar_credenciales_llavero, configurar_autostart, configurar_enlaces, enlaces_activos,
  guardar_credencial_rdp, preguntar_borrar_datos, simular_bloqueo, vigilar_bloqueo,
};

#[cfg(all(test, windows))]
mod pruebas {
  use super::windows_impl::{borrar_credenciales_con_prefijo, leer_credencial_rdp};
  use super::*;

  #[test]
  fn la_credencial_de_rdp_se_guarda_se_lee_y_se_borra() {
    let host = "ellkan-prueba.invalid";
    guardar_credencial_rdp(host, 3389, "DOMINIO\\ana", "Clave-ñ-€-Larga-123").expect("guardar");
    let (usuario, contrasena) = leer_credencial_rdp(host).expect("leer");
    assert_eq!(usuario, "DOMINIO\\ana");
    assert_eq!(contrasena, "Clave-ñ-€-Larga-123", "la contraseña vuelve idéntica (UTF-16, con acentos y símbolos)");
    borrar_credencial_rdp(host, 3389);
    assert!(leer_credencial_rdp(host).is_none(), "borrada");
  }

  #[test]
  fn con_un_puerto_distinto_se_dejan_las_dos_formas_del_nombre() {
    let host = "ellkan-prueba-2.invalid";
    guardar_credencial_rdp(host, 3390, "ana", "x").expect("guardar");
    assert!(leer_credencial_rdp(host).is_some());
    borrar_credencial_rdp(host, 3390);
    assert!(leer_credencial_rdp(host).is_none());
  }

  #[test]
  fn las_claves_del_llavero_de_la_app_se_borran_y_las_ajenas_no() {
    let propia = keyring::Entry::new("Ellkan", "vault_prueba-borrado").unwrap();
    let ajena = keyring::Entry::new("OtraApp", "vault_prueba-borrado").unwrap();
    propia.set_password("envoltura").unwrap();
    ajena.set_password("no la toques").unwrap();

    // Con un prefijo propio de la prueba: la función real (`vault_`) borraría también
    // las claves de tu bóveda de verdad.
    let borradas = borrar_credenciales_con_prefijo("vault_prueba-borrado");

    assert!(borradas >= 1, "se borró al menos la de Ellkan");
    assert!(matches!(propia.get_password(), Err(keyring::Error::NoEntry)), "la de Ellkan ya no está");
    assert_eq!(ajena.get_password().unwrap(), "no la toques", "la de otra aplicación sigue");
    ajena.delete_credential().unwrap();
  }

  #[test]
  fn borrar_lo_que_no_existe_no_falla() {
    borrar_credencial_rdp("ellkan-no-existe.invalid", 3389);
  }
}

#[cfg(not(windows))]
mod otros {
  const NO_SOPORTADO: &str = "esta función sólo está disponible en Windows por ahora";
  pub fn autostart_activo() -> bool {
    false
  }
  pub fn configurar_autostart(_activo: bool) -> Result<(), String> {
    Err(NO_SOPORTADO.to_string())
  }
  pub fn enlaces_activos() -> bool {
    false
  }
  pub fn configurar_enlaces(_activo: bool) -> Result<(), String> {
    Err(NO_SOPORTADO.to_string())
  }
  pub fn preguntar_borrar_datos() -> bool {
    false
  }
  pub fn borrar_credenciales_llavero() -> usize {
    0
  }
}
#[cfg(not(windows))]
pub use otros::{autostart_activo, borrar_credenciales_llavero, configurar_autostart, configurar_enlaces, enlaces_activos, preguntar_borrar_datos};

#[cfg(test)]
mod pruebas_de_borrado {
  use super::borrar_carpeta_de_datos;

  fn temporal(nombre: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("ellkan_test_borrado_{nombre}_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
  }

  #[test]
  fn una_carpeta_de_datos_propia_se_borra_con_todo_lo_que_tiene() {
    let raiz = temporal("propia");
    let datos = raiz.join("Ellkan");
    std::fs::create_dir_all(datos.join("backups")).unwrap();
    std::fs::write(datos.join("ellkan.db"), b"x").unwrap();
    std::fs::write(datos.join("backups").join("copia.db"), b"x").unwrap();

    borrar_carpeta_de_datos(&datos).expect("borrar");

    assert!(!datos.exists());
    assert!(raiz.exists(), "la carpeta de arriba no se toca");
    std::fs::remove_dir_all(raiz).unwrap();
  }

  #[test]
  fn una_carpeta_que_no_es_de_ellkan_se_rechaza_y_no_se_toca() {
    let raiz = temporal("ajena");
    let ajena = raiz.join("Documentos");
    std::fs::create_dir_all(&ajena).unwrap();
    std::fs::write(ajena.join("importante.txt"), b"x").unwrap();

    assert!(borrar_carpeta_de_datos(&ajena).is_err());
    assert!(ajena.join("importante.txt").exists());
    // Ni una raíz, aunque se llame igual.
    assert!(borrar_carpeta_de_datos(std::path::Path::new("Ellkan")).is_err());
    assert!(borrar_carpeta_de_datos(std::path::Path::new("C:\\Ellkan")).is_err());
    std::fs::remove_dir_all(raiz).unwrap();
  }

  #[test]
  fn borrar_lo_que_ya_no_existe_no_es_un_error() {
    let raiz = temporal("inexistente");
    assert!(borrar_carpeta_de_datos(&raiz.join("Ellkan")).is_ok());
    std::fs::remove_dir_all(raiz).unwrap();
  }
}
