// Autor: Athan Espinoza

//! Host de native messaging (F-56, fase 1): el navegador lo lanza cuando la
//! extensión de Ellkan abre el canal `com.ellkan.desktop`, y le pasa sus
//! pedidos por stdin. El host los reenvía a la app de escritorio por la
//! tubería con nombre que la app publica en `desktop.json` (ver
//! `canal_extension.rs`) y devuelve las respuestas por stdout. No hay ningún
//! puerto TCP de por medio.
//!
//! Sólo biblioteca estándar + `serde_json`: no enlaza Tauri ni el backend
//! (sería un ejecutable de decenas de MB para reenviar bytes).
//!
//! Protocolo de native messaging: cada mensaje es JSON con un prefijo de 4
//! bytes (largo, en el orden de bytes de la máquina — little-endian en
//! Windows). Del host a la extensión cada mensaje puede pesar hasta 1 MB, así
//! que la respuesta se manda en partes `{"id", "parte", "total", "datos"}` y
//! la extensión la rearma (una lista grande de recursos o un avatar no entran
//! en un solo mensaje).

use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::time::Duration;

use serde_json::{json, Value};

/// Tope de un pedido de la extensión (los suyos son chicos).
const MAX_PEDIDO: usize = 16 * 1024 * 1024;
/// Tamaño de cada parte hacia la extensión, holgado bajo el límite de 1 MB.
const TAMANO_PARTE: usize = 512 * 1024;

fn leer_mensaje(entrada: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
  let mut largo = [0u8; 4];
  match entrada.read_exact(&mut largo) {
    Ok(()) => {}
    // El navegador cerró el canal: fin normal.
    Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
    Err(e) => return Err(e),
  }
  let largo = u32::from_le_bytes(largo) as usize;
  if largo > MAX_PEDIDO {
    return Err(io::Error::other("pedido demasiado grande"));
  }
  let mut bytes = vec![0u8; largo];
  entrada.read_exact(&mut bytes)?;
  Ok(Some(bytes))
}

fn escribir_mensaje(salida: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
  salida.write_all(&(bytes.len() as u32).to_le_bytes())?;
  salida.write_all(bytes)?;
  salida.flush()
}

/// `desktop.json` de la app en curso. El navegador lanza el host sin el
/// entorno de la app, así que primero se busca el del modo portable (junto a
/// este ejecutable), después `ELLKAN_CONFIG_DIR` y por último `~/.ellkan`.
fn desktop_json() -> Option<PathBuf> {
  let mut candidatos = Vec::new();
  if let Some(carpeta) = std::env::current_exe().ok().and_then(|e| e.parent().map(PathBuf::from)) {
    candidatos.push(carpeta.join("ellkan-datos").join("config").join("desktop.json"));
  }
  if let Some(config) = std::env::var_os("ELLKAN_CONFIG_DIR") {
    candidatos.push(PathBuf::from(config).join("desktop.json"));
  }
  if let Some(perfil) = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME")) {
    candidatos.push(PathBuf::from(perfil).join(".ellkan").join("desktop.json"));
  }
  candidatos.into_iter().find(|c| c.is_file())
}

fn nombre_de_tuberia() -> Option<String> {
  let datos: Value = serde_json::from_slice(&std::fs::read(desktop_json()?).ok()?).ok()?;
  datos.get("pipe")?.as_str().map(str::to_string)
}

/// Reenvía un pedido a la app por la tubería y devuelve su respuesta.
fn reenviar(pedido: &[u8]) -> Result<Vec<u8>, String> {
  let nombre = nombre_de_tuberia().ok_or("app_cerrada")?;
  let ruta = format!(r"\\.\pipe\{nombre}");
  // Si todas las instancias están ocupadas (varios pedidos a la vez), se reintenta un poco.
  let mut tuberia = None;
  for _ in 0..40 {
    match std::fs::OpenOptions::new().read(true).write(true).open(&ruta) {
      Ok(t) => {
        tuberia = Some(t);
        break;
      }
      // 231 = ERROR_PIPE_BUSY
      Err(e) if e.raw_os_error() == Some(231) => std::thread::sleep(Duration::from_millis(50)),
      // La tubería no existe: la app no está abierta (o es de un arranque anterior).
      Err(_) => return Err("app_cerrada".into()),
    }
  }
  let mut tuberia = tuberia.ok_or("app_ocupada")?;
  escribir_mensaje(&mut tuberia, pedido).map_err(|e| e.to_string())?;
  leer_mensaje(&mut tuberia).map_err(|e| e.to_string())?.ok_or_else(|| "la app cerró la conexión".into())
}

/// Manda la respuesta a la extensión en partes de hasta `TAMANO_PARTE`.
fn responder(salida: &mut impl Write, id: &Value, respuesta: &str) -> io::Result<()> {
  let mut partes = Vec::new();
  let mut inicio = 0;
  while inicio < respuesta.len() || partes.is_empty() {
    let mut fin = (inicio + TAMANO_PARTE).min(respuesta.len());
    while !respuesta.is_char_boundary(fin) {
      fin -= 1;
    }
    partes.push(&respuesta[inicio..fin]);
    inicio = fin;
  }
  let total = partes.len();
  for (i, datos) in partes.into_iter().enumerate() {
    let mensaje = json!({ "id": id, "parte": i, "total": total, "datos": datos });
    escribir_mensaje(salida, &serde_json::to_vec(&mensaje).map_err(io::Error::other)?)?;
  }
  Ok(())
}

fn main() {
  let mut entrada = io::stdin().lock();
  let mut salida = io::stdout().lock();
  loop {
    let pedido = match leer_mensaje(&mut entrada) {
      Ok(Some(p)) => p,
      Ok(None) | Err(_) => return,
    };
    let id = serde_json::from_slice::<Value>(&pedido).ok().and_then(|v| v.get("id").cloned()).unwrap_or(Value::Null);
    let respuesta = match reenviar(&pedido) {
      Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
      Err(error) => json!({ "id": id, "error": error }).to_string(),
    };
    if responder(&mut salida, &id, &respuesta).is_err() {
      return;
    }
  }
}

#[cfg(test)]
mod pruebas {
  use super::*;

  /// Lee los mensajes que escribió `responder` y rearma la respuesta, como la extensión.
  fn rearmar(salida: &[u8]) -> (usize, String) {
    let mut cursor = io::Cursor::new(salida);
    let mut partes = Vec::new();
    while let Some(m) = leer_mensaje(&mut cursor).unwrap() {
      assert!(m.len() <= 1024 * 1024, "ningún mensaje al navegador puede pasar de 1 MB");
      let v: Value = serde_json::from_slice(&m).unwrap();
      partes.push(v["datos"].as_str().unwrap().to_string());
    }
    (partes.len(), partes.concat())
  }

  #[test]
  fn una_respuesta_grande_se_parte_bajo_1_mb_y_se_rearma_igual() {
    // ~2.6 MB con caracteres de 2 bytes, para que algún corte caiga en medio de uno.
    let respuesta = format!("{{\"id\":7,\"cuerpo_b64\":\"{}\"}}", "ñá".repeat(650_000));
    let mut salida = Vec::new();
    responder(&mut salida, &json!(7), &respuesta).unwrap();
    let (partes, rearmada) = rearmar(&salida);
    assert!(partes > 1);
    assert_eq!(rearmada, respuesta);
  }

  #[test]
  fn una_respuesta_chica_va_en_un_solo_mensaje() {
    let mut salida = Vec::new();
    responder(&mut salida, &json!(1), "{\"id\":1,\"ok\":true}").unwrap();
    assert_eq!(rearmar(&salida), (1, "{\"id\":1,\"ok\":true}".to_string()));
  }
}
