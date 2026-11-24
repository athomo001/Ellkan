// Autor: Athan Espinoza

//! «Usar mi cuenta de un servidor» desde el login de la app, cuando el equipo
//! ya tiene una bóveda con otra cuenta (la app tiene una sola cuenta por
//! equipo). La bóveda actual NO se borra: se guarda entera en `backups/` y la
//! app arranca como recién instalada, en el paso de conectar con un servidor.
//!
//! En dos tiempos, como `borrado_remoto`: con la app corriendo la base está
//! abierta y en Windows no se puede mover un archivo en uso.
//! 1. `marcar`: deja la marca y la app se reinicia.
//! 2. `ejecutar`: al arrancar, ANTES de abrir la base, consolida el `-wal` en
//!    `ellkan.db` y la mueve a `backups/` (un solo archivo, se abre tal cual).
//!    Si algo falla, la marca queda y se reintenta en el próximo arranque;
//!    mientras tanto la bóveda vieja sigue intacta en su lugar.

use std::path::{Path, PathBuf};

use anyhow::Context;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

use super::respaldos::{carpeta_de_respaldos, marca_de_tiempo};

/// Nombre de la marca, dentro de la carpeta de datos.
pub const MARCA: &str = "archivar-boveda-pendiente";
/// Prefijo propio: la poda de copias (`respaldos::podar`) nunca lo toca.
pub const PREFIJO: &str = "ellkan-archivada-";

pub fn pendiente(datadir: &Path) -> bool {
    datadir.join(MARCA).exists()
}

pub fn marcar(datadir: &Path) -> std::io::Result<()> {
    std::fs::write(datadir.join(MARCA), b"")
}

/// Mueve la bóveda a `backups/` y quita la marca. Devuelve dónde quedó la
/// copia (`None` si no había bóveda).
pub async fn ejecutar(datadir: &Path) -> anyhow::Result<Option<PathBuf>> {
    let base = datadir.join("ellkan.db");
    let mut copia = None;
    if base.exists() {
        // Todo lo que esté en el `-wal` pasa al `.db` y el `-wal` queda vacío:
        // la copia es un solo archivo completo, sin depender de mover tres.
        let opciones = SqliteConnectOptions::new().filename(&base).create_if_missing(false);
        let pool = SqlitePoolOptions::new().max_connections(1).connect_with(opciones).await.context("no se pudo abrir la bóveda para archivarla")?;
        sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)").execute(&pool).await.context("no se pudo consolidar la bóveda antes de archivarla")?;
        pool.close().await;

        let carpeta = carpeta_de_respaldos(datadir);
        std::fs::create_dir_all(&carpeta).with_context(|| format!("no se pudo crear {}", carpeta.display()))?;
        let mut destino = carpeta.join(format!("{PREFIJO}{}.db", marca_de_tiempo()));
        let mut n = 1;
        while destino.exists() {
            destino = carpeta.join(format!("{PREFIJO}{}-{n}.db", marca_de_tiempo()));
            n += 1;
        }
        std::fs::rename(&base, &destino).with_context(|| format!("no se pudo mover {}", base.display()))?;
        // Ya vacíos tras el checkpoint: que la bóveda nueva no los herede.
        for sufijo in ["-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{sufijo}", base.display()));
        }
        copia = Some(destino);
    }
    std::fs::remove_file(datadir.join(MARCA)).context("no se pudo quitar la marca de archivado")?;
    Ok(copia)
}
