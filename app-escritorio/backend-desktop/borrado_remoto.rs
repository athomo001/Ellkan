// Autor: Athan Espinoza

//! Revocación remota (docs/revocacion-remota.md): el servidor vinculado avisó,
//! con un aviso firmado que ya verificó el frontend, que la cuenta fue
//! bloqueada o purgada. La bóveda local se borra entera.
//!
//! En dos tiempos, porque mientras la app corre la base SQLite está abierta y
//! en Windows no se puede borrar un archivo en uso:
//! 1. `marcar`: deja una marca en la carpeta de datos. Desde ese momento el
//!    backend local rechaza todo (ver `router`), así que ni la ventana ni la
//!    extensión pueden leer nada más.
//! 2. `ejecutar`: al próximo arranque, ANTES de abrir la base, borra todo. Si
//!    algo falla a mitad (un archivo bloqueado), la marca queda y se reintenta
//!    en el arranque siguiente: nunca se llega a pedir la contraseña con la
//!    bóveda vieja todavía en disco.

use std::path::Path;

/// Nombre de la marca, dentro de la carpeta de datos.
pub const MARCA: &str = "borrado-remoto-pendiente";

pub fn pendiente(datadir: &Path) -> bool {
    datadir.join(MARCA).exists()
}

/// Deja la marca. `servidor` sólo queda como referencia en el archivo.
pub fn marcar(datadir: &Path, servidor: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(datadir)?;
    std::fs::write(datadir.join(MARCA), format!("servidor: {servidor}\n"))
}

fn borrar_con_reintentos(ruta: &Path) -> std::io::Result<()> {
    let mut ultimo = None;
    for _ in 0..6 {
        let r = if ruta.is_dir() { std::fs::remove_dir_all(ruta) } else { std::fs::remove_file(ruta) };
        match r {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => {
                ultimo = Some(e);
                std::thread::sleep(std::time::Duration::from_millis(300));
            }
        }
    }
    Err(ultimo.unwrap_or_else(|| std::io::Error::other("no se pudo borrar")))
}

/// Borra TODO el contenido de la carpeta de datos (bóveda, `-wal`/`-shm`,
/// ajustes, copias de seguridad, claves del backend local) y, sólo si eso
/// salió completo, la marca. Antes, el archivo `ellkan-escritorio.json` de
/// cada extensión instalada desde la app (la dirección del backend local).
/// La carpeta de la extensión NO se borra a propósito: si desaparece, el
/// navegador la desactiva y su propia limpieza (cerrar sesión y purgar lo que
/// guardó, al recibir el 401 de la app vacía) nunca llega a correr.
pub fn ejecutar(datadir: &Path) -> anyhow::Result<()> {
    if let Ok(config) = super::cargar_config(datadir) {
        for navegador in &config.extension_navegadores {
            if let Some(objetivo) = super::extension::objetivo_de(navegador) {
                let archivo = super::extension::carpeta_de_instalacion(objetivo).join(super::extension::ARCHIVO_CONEXION);
                let _ = std::fs::remove_file(archivo);
            }
        }
    }

    // En modo portable la carpeta de la extensión vive dentro de la de datos
    // (`ELLKAN_EXTENSION_DIR` = `ellkan-datos/extension`): se respeta igual.
    let carpeta_extension = std::env::var_os("ELLKAN_EXTENSION_DIR").map(std::path::PathBuf::from);

    let mut errores = Vec::new();
    for entrada in std::fs::read_dir(datadir)? {
        let ruta = entrada?.path();
        if ruta.file_name().is_some_and(|n| n == MARCA) || carpeta_extension.as_deref() == Some(ruta.as_path()) {
            continue;
        }
        if let Err(e) = borrar_con_reintentos(&ruta) {
            errores.push(format!("{}: {e}", ruta.display()));
        }
    }
    if !errores.is_empty() {
        anyhow::bail!("borrado remoto incompleto, se reintenta en el próximo arranque: {}", errores.join("; "));
    }
    std::fs::remove_file(datadir.join(MARCA))?;
    Ok(())
}
