// Autor: Athan Espinoza

//! F-56, fase 1: canal entre la extensión de navegador y la app SIN puerto
//! TCP. Antes la extensión le hablaba al backend local por
//! `http://127.0.0.1:<puerto>`: tráfico en claro dentro de la máquina (con un
//! token de sesión) y un puerto que Windows a veces reserva.
//!
//! Ahora:
//!
//! ```text
//! extensión ──native messaging (stdio)──► ellkan_nm_host.exe ──tubería──► esta app
//! ```
//!
//! El navegador lanza `ellkan_nm_host.exe` (registrado por `registrar_host`)
//! y le pasa los pedidos de la extensión por stdin; el host los reenvía por
//! esta tubería con nombre y la app los ejecuta contra el MISMO router del
//! backend local, en el propio proceso (`tower::ServiceExt::oneshot`): no
//! pasa nada por la red, ni siquiera por 127.0.0.1.
//!
//! Protecciones de la tubería (mismo criterio que `tuberia.rs`):
//! - Nombre aleatorio de 128 bits, nuevo en cada arranque, publicado sólo en
//!   `desktop.json` (archivo privado del usuario).
//! - ACL sólo para el dueño (`D:P(A;;GA;;;OW)`) y sin clientes remotos.
//! - Sólo atiende al host oficial: el ejecutable del proceso que se conecta
//!   tiene que ser `ellkan_nm_host.exe` de la carpeta de esta app.
//!
//! Protocolo (igual en la tubería y en native messaging): mensajes JSON con
//! un prefijo de 4 bytes little-endian con su largo.
//! - Pedido: `{"id", "tipo": "ping"}` o
//!   `{"id", "tipo": "http", "metodo", "ruta", "headers": {..}, "cuerpo_b64"}`.
//! - Respuesta: `{"id", "ok": true}` (ping), `{"id", "status", "headers", "cuerpo_b64"}`
//!   o `{"id", "error"}`.

use std::ffi::c_void;
use std::os::windows::io::AsRawHandle;
use std::path::PathBuf;

use axum::body::Body;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tower::ServiceExt;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{LocalFree, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;

use crate::tuberia;

/// Nombre del host en los manifiestos de native messaging.
pub const NOMBRE_HOST: &str = "com.ellkan.desktop";

/// Ejecutable del host, junto al de la app.
pub const EJECUTABLE_HOST: &str = "ellkan_nm_host.exe";

/// Tope de un mensaje en la tubería (un avatar de 2 MB en base64 + margen).
const MAX_MENSAJE: usize = 16 * 1024 * 1024;

/// ID de la extensión en los navegadores Chromium. Es fijo porque su
/// manifiesto lleva `key` (la pública con la que se firma el `.crx`): igual
/// cargada desde carpeta que instalada. Sólo ese ID puede abrir el canal.
pub const ID_EXTENSION_CHROMIUM: &str = "elhbohglogkkcnkcjkecpjopoaiokfcj";

/// ID de la extensión en Firefox (`browser_specific_settings.gecko.id`).
pub const ID_EXTENSION_FIREFOX: &str = "extension@ellkan.local";

/// Escribe los manifiestos de native messaging en `<datos>/native-messaging/`
/// y los registra en cada navegador. Se llama en cada arranque: si la app se
/// movió de carpeta (o es la versión portable), el manifiesto apunta al host
/// de esta copia. Sin el host junto al ejecutable (por ejemplo, una
/// compilación incompleta) no registra nada.
pub fn registrar_host(datadir: &std::path::Path) -> Result<(), String> {
  let host = carpeta_de_la_app().map(|c| c.join(EJECUTABLE_HOST)).ok_or("no se encontró la carpeta de la app")?;
  if !host.is_file() {
    return Err(format!("no está {} junto a la app", host.display()));
  }
  let carpeta = datadir.join("native-messaging");
  std::fs::create_dir_all(&carpeta).map_err(|e| e.to_string())?;
  let ruta = host.display().to_string();
  let chromium = carpeta.join(format!("{NOMBRE_HOST}.json"));
  let firefox = carpeta.join(format!("{NOMBRE_HOST}.firefox.json"));
  let comun = |permitidos: Value| {
    let mut m = json!({ "name": NOMBRE_HOST, "description": "Ellkan: canal entre la extensión y la app de escritorio", "path": ruta, "type": "stdio" });
    m.as_object_mut().expect("objeto").extend(permitidos.as_object().expect("objeto").clone());
    serde_json::to_vec_pretty(&m).expect("serializar el manifiesto no falla")
  };
  std::fs::write(&chromium, comun(json!({ "allowed_origins": [format!("chrome-extension://{ID_EXTENSION_CHROMIUM}/")] }))).map_err(|e| e.to_string())?;
  std::fs::write(&firefox, comun(json!({ "allowed_extensions": [ID_EXTENSION_FIREFOX] }))).map_err(|e| e.to_string())?;
  crate::sistema::registrar_host_nativo(&chromium, &firefox)
}

/// Carpeta del ejecutable de la app (donde también vive el host).
pub fn carpeta_de_la_app() -> Option<PathBuf> {
  std::env::current_exe().ok()?.parent().map(PathBuf::from)
}

fn crear(ruta: &str, primera: bool) -> std::io::Result<NamedPipeServer> {
  let sddl: Vec<u16> = "D:P(A;;GA;;;OW)".encode_utf16().chain(std::iter::once(0)).collect();
  let mut descriptor = PSECURITY_DESCRIPTOR::default();
  // SAFETY: SDDL terminado en 0; el descriptor se libera con `LocalFree` abajo.
  unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(sddl.as_ptr()), SDDL_REVISION_1, &mut descriptor, None) }
    .map_err(std::io::Error::other)?;
  let mut atributos = SECURITY_ATTRIBUTES {
    nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
    lpSecurityDescriptor: descriptor.0,
    bInheritHandle: false.into(),
  };
  // SAFETY: los atributos son válidos durante la llamada.
  let servidor = unsafe {
    ServerOptions::new()
      .first_pipe_instance(primera)
      .reject_remote_clients(true)
      .create_with_security_attributes_raw(ruta, &mut atributos as *mut SECURITY_ATTRIBUTES as *mut c_void)
  };
  // SAFETY: el descriptor salió de `ConvertString...` y ya no se usa.
  unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
  servidor
}

/// Arranca el servidor de la tubería; devuelve su nombre corto (para
/// `desktop.json`). Corre en el runtime de Tauri hasta que la app termina.
pub fn iniciar(router: axum::Router) -> Result<String, String> {
  let nombre = tuberia::nombre_aleatorio()?.replacen("ellkan-conectar-", "ellkan-app-", 1);
  let ruta = tuberia::ruta_de(&nombre);
  let host_esperado = carpeta_de_la_app().map(|c| c.join(EJECUTABLE_HOST)).ok_or("no se encontró la carpeta de la app")?;
  let primera = crear(&ruta, true).map_err(|e| format!("no se pudo crear la tubería de la extensión: {e}"))?;

  tauri::async_runtime::spawn(async move {
    let mut servidor = primera;
    loop {
      if let Err(e) = servidor.connect().await {
        log::warn!("tubería de la extensión: conexión fallida: {e}");
      }
      let conectado = servidor;
      servidor = match crear(&ruta, false) {
        Ok(s) => s,
        Err(e) => {
          log::error!("tubería de la extensión: no se pudo seguir escuchando: {e}");
          return;
        }
      };
      tauri::async_runtime::spawn(atender(conectado, router.clone(), host_esperado.clone()));
    }
  });
  Ok(nombre)
}

async fn atender(mut tuberia_cliente: NamedPipeServer, router: axum::Router, host_esperado: PathBuf) {
  // Sólo el host oficial de esta app puede hablar por acá.
  let mut pid = 0u32;
  // SAFETY: el handle es el de la tubería conectada, válido mientras vive `tuberia_cliente`.
  let pid_ok = unsafe { GetNamedPipeClientProcessId(HANDLE(tuberia_cliente.as_raw_handle()), &mut pid) }.is_ok();
  let es_el_host = pid_ok && tuberia::ejecutable_de(pid).is_some_and(|exe| tuberia::misma_ruta(&exe, &host_esperado));
  if !es_el_host {
    log::warn!("tubería de la extensión: se rechazó un cliente que no es {EJECUTABLE_HOST} (pid {pid})");
    return;
  }

  let pedido = match leer_mensaje(&mut tuberia_cliente).await {
    Ok(p) => p,
    Err(e) => {
      log::warn!("tubería de la extensión: pedido ilegible: {e}");
      return;
    }
  };
  let respuesta = responder(&pedido, router).await;
  let _ = escribir_mensaje(&mut tuberia_cliente, &respuesta).await;
}

async fn leer_mensaje(tuberia_cliente: &mut NamedPipeServer) -> std::io::Result<Value> {
  let largo = tuberia_cliente.read_u32_le().await? as usize;
  if largo > MAX_MENSAJE {
    return Err(std::io::Error::other("mensaje demasiado grande"));
  }
  let mut bytes = vec![0u8; largo];
  tuberia_cliente.read_exact(&mut bytes).await?;
  serde_json::from_slice(&bytes).map_err(std::io::Error::other)
}

async fn escribir_mensaje(tuberia_cliente: &mut NamedPipeServer, valor: &Value) -> std::io::Result<()> {
  let bytes = serde_json::to_vec(valor).map_err(std::io::Error::other)?;
  tuberia_cliente.write_u32_le(bytes.len() as u32).await?;
  tuberia_cliente.write_all(&bytes).await?;
  tuberia_cliente.flush().await
}

/// Último contacto de la extensión (segundos Unix), para registrar en
/// `Ellkan.log` cuándo se conecta y cuándo vuelve tras un rato callada, sin
/// una línea por cada ping (pedido 2026-10-18: ver en el log si la
/// comunicación con la extensión anda).
static ULTIMO_CONTACTO: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Más de esto sin noticias = la próxima vez se registra como reconexión.
const SILENCIO_RECONEXION_S: u64 = 300;

fn anotar_contacto() {
  use std::sync::atomic::Ordering;
  let ahora = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
  let antes = ULTIMO_CONTACTO.swap(ahora, Ordering::Relaxed);
  if antes == 0 {
    log::info!("extensión: conectada por native messaging");
  } else if ahora.saturating_sub(antes) > SILENCIO_RECONEXION_S {
    log::info!("extensión: volvió a conectarse ({} min sin contacto)", (ahora - antes) / 60);
  }
}

/// Ejecuta el pedido contra el router del backend local, en este proceso.
async fn responder(pedido: &Value, router: axum::Router) -> Value {
  anotar_contacto();
  let id = pedido.get("id").cloned().unwrap_or(Value::Null);
  match pedido.get("tipo").and_then(Value::as_str) {
    Some("ping") => json!({ "id": id, "ok": true }),
    Some("http") => match ejecutar_http(pedido, router).await {
      Ok(mut r) => {
        r["id"] = id;
        r
      }
      Err(e) => json!({ "id": id, "error": e }),
    },
    _ => json!({ "id": id, "error": "tipo de pedido desconocido" }),
  }
}

fn sin_consulta(ruta: &str) -> &str {
  ruta.split('?').next().unwrap_or(ruta)
}

async fn ejecutar_http(pedido: &Value, router: axum::Router) -> Result<Value, String> {
  let metodo = pedido.get("metodo").and_then(Value::as_str).ok_or("falta el método")?;
  let ruta = pedido.get("ruta").and_then(Value::as_str).ok_or("falta la ruta")?;
  // Sólo rutas del propio backend: nunca una URL absoluta hacia otro lado.
  if !ruta.starts_with('/') || ruta.starts_with("//") {
    return Err("ruta inválida".into());
  }
  let cuerpo = match pedido.get("cuerpo_b64").and_then(Value::as_str) {
    Some(b64) => ellkan_backend::b64::decode(b64).map_err(|_| "cuerpo_b64 inválido")?,
    None => Vec::new(),
  };

  let mut armado = axum::http::Request::builder().method(metodo).uri(ruta);
  if let Some(headers) = pedido.get("headers").and_then(Value::as_object) {
    for (nombre, valor) in headers {
      // `Host`/`Origin` no aplican: el pedido no viene de ningún navegador web.
      if nombre.eq_ignore_ascii_case("host") || nombre.eq_ignore_ascii_case("origin") {
        continue;
      }
      if let Some(v) = valor.as_str() {
        armado = armado.header(nombre.as_str(), v);
      }
    }
  }
  let solicitud = armado.body(Body::from(cuerpo)).map_err(|e| format!("pedido inválido: {e}"))?;
  let inicio = std::time::Instant::now();
  let respuesta = router.oneshot(solicitud).await.map_err(|e| {
    log::warn!("extensión: {metodo} {} → falló: {e}", sin_consulta(ruta));
    format!("{e}")
  })?;

  let status = respuesta.status().as_u16();
  // Sin la consulta (`?…`): el autofill manda ahí la URL del sitio que se
  // está visitando, y eso no va al log.
  let linea = format!("extensión: {metodo} {} → {status} ({} ms)", sin_consulta(ruta), inicio.elapsed().as_millis());
  match status {
    500.. => log::error!("{linea}"),
    400..=499 if status != 404 => log::warn!("{linea}"),
    _ => log::info!("{linea}"),
  }
  let mut headers = serde_json::Map::new();
  for (nombre, valor) in respuesta.headers() {
    if let Ok(v) = valor.to_str() {
      headers.insert(nombre.as_str().to_string(), Value::String(v.to_string()));
    }
  }
  let bytes = axum::body::to_bytes(respuesta.into_body(), MAX_MENSAJE).await.map_err(|e| format!("{e}"))?;
  ellkan_backend::desktop::cambios_extension::avisar(metodo, sin_consulta(ruta), status, &bytes);
  Ok(json!({ "status": status, "headers": headers, "cuerpo_b64": ellkan_backend::b64::encode(&bytes) }))
}
