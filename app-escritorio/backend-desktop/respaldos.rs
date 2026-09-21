// Autor: Athan Espinoza

//! Copias de seguridad de la bóveda local (F-53). En la app de escritorio el
//! archivo `ellkan.db` es la ÚNICA copia de los datos del usuario: no hay un
//! servidor del que recuperarlos. Por eso, antes de aplicar migraciones
//! pendientes (una versión nueva de la app puede cambiar el esquema) se guarda
//! una copia, y el usuario puede pedir otra cuando quiera.
//!
//! La copia se hace con `VACUUM INTO`, que produce un archivo SQLite completo
//! y consistente aunque haya escrituras en curso (copiar el `.db` a mano con
//! WAL activo podría dejar un archivo a medias). Lo que se copia sigue
//! cifrado igual que en la bóveda: nada sale en claro.

use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::Serialize;
use sqlx::SqlitePool;
use time::OffsetDateTime;

/// Cuántas copias se conservan de cada tipo (automáticas / manuales).
pub const RETENCION: usize = 5;

pub const PREFIJO_AUTOMATICO: &str = "ellkan-antes-de-migrar-";
pub const PREFIJO_MANUAL: &str = "ellkan-manual-";

/// Carpeta donde quedan las copias: `<datadir>/backups`.
pub fn carpeta_de_respaldos(datadir: &Path) -> PathBuf {
    datadir.join("backups")
}

fn marca_de_tiempo() -> String {
    let t = OffsetDateTime::now_utc();
    format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}-{:03}",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second(),
        t.millisecond()
    )
}

/// `Some(última versión aplicada)` si la base ya tiene migraciones aplicadas y
/// `migrator` trae alguna que todavía no. `None` si no hay nada pendiente o si
/// la base es nueva (no hay nada que proteger).
pub async fn version_previa_si_hay_pendientes(pool: &SqlitePool, migrator: &sqlx::migrate::Migrator) -> anyhow::Result<Option<i64>> {
    let existe: i64 = sqlx::query_scalar("select count(*) from sqlite_master where type = 'table' and name = '_sqlx_migrations'")
        .fetch_one(pool)
        .await?;
    if existe == 0 {
        return Ok(None);
    }
    let aplicadas: Vec<i64> = sqlx::query_scalar("select version from _sqlx_migrations where success = 1").fetch_all(pool).await?;
    let Some(ultima) = aplicadas.iter().max().copied() else {
        return Ok(None);
    };
    let hay_pendientes = migrator.iter().any(|m| !aplicadas.contains(&m.version));
    Ok(hay_pendientes.then_some(ultima))
}

/// Guarda una copia consistente de la base en `<datadir>/backups/` y poda las
/// más viejas del mismo tipo (`prefijo`) dejando `RETENCION`. `etiqueta` va en
/// el nombre (por ejemplo la versión del esquema de la que se partió).
pub async fn respaldar(pool: &SqlitePool, datadir: &Path, prefijo: &str, etiqueta: &str) -> anyhow::Result<PathBuf> {
    let carpeta = carpeta_de_respaldos(datadir);
    std::fs::create_dir_all(&carpeta).with_context(|| format!("no se pudo crear {}", carpeta.display()))?;

    let mut destino = carpeta.join(format!("{prefijo}{etiqueta}{}.db", marca_de_tiempo()));
    let mut n = 1;
    while destino.exists() {
        destino = carpeta.join(format!("{prefijo}{etiqueta}{}-{n}.db", marca_de_tiempo()));
        n += 1;
    }

    // `VACUUM INTO` no acepta un archivo que ya exista (por eso el bucle de
    // arriba) y sí acepta el destino como parámetro.
    sqlx::query("VACUUM INTO ?1")
        .bind(destino.to_string_lossy().into_owned())
        .execute(pool)
        .await
        .with_context(|| format!("no se pudo escribir la copia de seguridad en {}", destino.display()))?;

    podar(&carpeta, prefijo, RETENCION)?;
    Ok(destino)
}

/// Borra las copias más viejas con este `prefijo`, dejando las `conservar`
/// más nuevas. El nombre lleva la fecha con milisegundos, así que ordenar por
/// nombre es ordenar por antigüedad.
fn podar(carpeta: &Path, prefijo: &str, conservar: usize) -> anyhow::Result<()> {
    let mut nombres: Vec<String> = std::fs::read_dir(carpeta)?
        .filter_map(Result::ok)
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.starts_with(prefijo) && n.ends_with(".db"))
        .collect();
    nombres.sort();
    let sobran = nombres.len().saturating_sub(conservar);
    for nombre in nombres.into_iter().take(sobran) {
        std::fs::remove_file(carpeta.join(&nombre)).with_context(|| format!("no se pudo borrar la copia vieja {nombre}"))?;
    }
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct Respaldo {
    pub nombre: String,
    pub bytes: u64,
    /// Segundos Unix de la última modificación.
    pub creado_unix: u64,
    /// `true` si la hizo la app antes de migrar, `false` si la pidió el usuario.
    pub automatico: bool,
}

/// Copias existentes, la más nueva primero. Crea la carpeta si no existe.
pub fn listar(datadir: &Path) -> anyhow::Result<Vec<Respaldo>> {
    let carpeta = carpeta_de_respaldos(datadir);
    std::fs::create_dir_all(&carpeta).with_context(|| format!("no se pudo crear {}", carpeta.display()))?;
    let mut respaldos: Vec<Respaldo> = std::fs::read_dir(&carpeta)?
        .filter_map(Result::ok)
        .filter_map(|e| {
            let nombre = e.file_name().into_string().ok()?;
            let automatico = nombre.starts_with(PREFIJO_AUTOMATICO);
            if !(automatico || nombre.starts_with(PREFIJO_MANUAL)) || !nombre.ends_with(".db") {
                return None;
            }
            let meta = e.metadata().ok()?;
            let creado_unix = meta.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
            Some(Respaldo { nombre, bytes: meta.len(), creado_unix, automatico })
        })
        .collect();
    respaldos.sort_by(|a, b| b.creado_unix.cmp(&a.creado_unix).then_with(|| b.nombre.cmp(&a.nombre)));
    Ok(respaldos)
}
