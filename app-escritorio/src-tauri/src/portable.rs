// Autor: Athan Espinoza

//! Modo portable (F-54): la app y TODOS sus datos en una carpeta que se puede
//! llevar en un pendrive, sin dejar nada en `%APPDATA%` ni en el perfil del
//! usuario de la PC donde se use.
//!
//! Se activa con `--portable` en la línea de comandos o poniendo un archivo
//! `ellkan-portable.txt` junto al `.exe` (así alcanza con copiar la carpeta:
//! no hace falta un acceso directo con argumentos).

use std::path::{Path, PathBuf};

pub const BANDERA: &str = "--portable";
pub const MARCA: &str = "ellkan-portable.txt";
const CARPETA_DE_DATOS: &str = "ellkan-datos";

fn carpeta_del_exe() -> Option<PathBuf> {
  std::env::current_exe().ok()?.parent().map(Path::to_path_buf)
}

/// ¿Se está corriendo en modo portable?
pub fn activo() -> bool {
  std::env::args().any(|a| a == BANDERA) || carpeta_del_exe().is_some_and(|c| c.join(MARCA).is_file())
}

/// `<carpeta del .exe>/ellkan-datos`, sólo en modo portable.
pub fn carpeta_de_datos() -> Option<PathBuf> {
  if !activo() {
    return None;
  }
  carpeta_del_exe().map(|c| c.join(CARPETA_DE_DATOS))
}

/// Redirige a la carpeta portable lo que vive FUERA del directorio de datos:
/// `desktop.json` (vía `ELLKAN_CONFIG_DIR`) y la carpeta de la extensión de
/// navegador. Respeta lo que el usuario ya haya fijado a mano.
///
/// Hay que llamarla al principio de `run()`, antes de crear ningún hilo.
pub fn preparar() {
  let Some(datos) = carpeta_de_datos() else { return };
  for (variable, subcarpeta) in [("ELLKAN_CONFIG_DIR", "config"), ("ELLKAN_EXTENSION_DIR", "extension")] {
    if std::env::var_os(variable).is_none() {
      // SAFETY: se ejecuta al inicio de `run()`, cuando todavía no hay más
      // hilos que lean el entorno (ni Tauri, ni tokio, ni el backend).
      unsafe { std::env::set_var(variable, datos.join(subcarpeta)) };
    }
  }
}
