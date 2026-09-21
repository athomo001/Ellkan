// Autor: Athan Espinoza

//! Guardar archivos que la ventana "descarga" (el recovery kit, exportaciones
//! KDBX/CSV/CXF, los `.7z` cifrados). El webview de Tauri no procesa un
//! `<a download>` sobre un blob — el clic no hace nada, sin ningún error — así
//! que en escritorio el archivo lo escribe el backend en la carpeta Descargas
//! del usuario y le devuelve la ruta a la interfaz.
//!
//! Lo que llega acá viene del frontend, así que el nombre se trata como no
//! confiable: se reduce a un nombre de archivo (sin carpetas), se limpian los
//! caracteres que Windows no acepta y nunca se pisa un archivo existente.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};

/// Carpeta Descargas del usuario (la real de Windows/Linux, aunque esté
/// redirigida), creándola si no existe.
pub fn carpeta_descargas() -> anyhow::Result<PathBuf> {
    let carpeta = dirs::download_dir()
        .or_else(|| dirs::home_dir().map(|h| h.join("Downloads")))
        .context("no se pudo resolver la carpeta Descargas del usuario")?;
    std::fs::create_dir_all(&carpeta).with_context(|| format!("no se pudo crear {}", carpeta.display()))?;
    Ok(carpeta)
}

const RESERVADOS_WINDOWS: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3",
    "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Reduce `nombre` a un nombre de archivo seguro para cualquier sistema:
/// sin componentes de carpeta, sin caracteres inválidos en Windows, sin
/// nombres de dispositivo reservados y con largo acotado. `None` si no queda
/// nada utilizable.
pub fn nombre_seguro(nombre: &str) -> Option<String> {
    // Sólo la última parte: `..\..\x.txt` o `/etc/x` quedan en `x.txt`.
    let ultimo = nombre.rsplit(['/', '\\']).next().unwrap_or("");
    let limpio: String = ultimo
        .chars()
        .map(|c| if c.is_control() || "<>:\"|?*".contains(c) { '_' } else { c })
        .collect();
    // Windows no admite puntos ni espacios al final del nombre.
    let limpio = limpio.trim().trim_end_matches('.').trim_end().to_string();
    if limpio.is_empty() || limpio.chars().all(|c| c == '.' || c == '_') {
        return None;
    }

    let (base, extension) = match limpio.rsplit_once('.') {
        Some((b, e)) if !b.is_empty() => (b.to_string(), format!(".{e}")),
        _ => (limpio.clone(), String::new()),
    };
    let base = if RESERVADOS_WINDOWS.contains(&base.to_uppercase().as_str()) { format!("_{base}") } else { base };

    let mut resultado = format!("{base}{extension}");
    if resultado.chars().count() > 150 {
        let base_corta: String = base.chars().take(150usize.saturating_sub(extension.chars().count())).collect();
        resultado = format!("{base_corta}{extension}");
    }
    Some(resultado)
}

/// Escribe `contenido` en `carpeta` con `nombre` (ya saneado). Si ya existe un
/// archivo con ese nombre no lo toca: prueba `nombre (1).ext`, `nombre (2).ext`…
/// La creación es atómica (`create_new`), así que ni siquiera una carrera con
/// otro proceso puede hacer que se pise algo.
pub fn guardar_sin_pisar(carpeta: &Path, nombre: &str, contenido: &[u8]) -> anyhow::Result<PathBuf> {
    let Some(nombre) = nombre_seguro(nombre) else {
        bail!("el nombre del archivo no es válido");
    };
    let (base, extension) = match nombre.rsplit_once('.') {
        Some((b, e)) if !b.is_empty() => (b.to_string(), format!(".{e}")),
        _ => (nombre.clone(), String::new()),
    };

    for intento in 0..1000 {
        let candidato = if intento == 0 { nombre.clone() } else { format!("{base} ({intento}){extension}") };
        let ruta = carpeta.join(&candidato);
        match std::fs::OpenOptions::new().write(true).create_new(true).open(&ruta) {
            Ok(mut archivo) => {
                archivo.write_all(contenido).with_context(|| format!("no se pudo escribir {}", ruta.display()))?;
                return Ok(ruta);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e).with_context(|| format!("no se pudo crear {}", ruta.display())),
        }
    }
    bail!("ya hay demasiados archivos con el nombre {nombre:?} en {}", carpeta.display())
}
