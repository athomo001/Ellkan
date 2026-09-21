// Autor: Athan Espinoza

//! Helpers compartidos por las implementaciones SQLite de repository (modo
//! escritorio) — sin `sqlx::query!`/`query_as!` (spec/13 §4: no hay forma de
//! que la macro sepa a qué dialecto apunta cada invocación con
//! `postgres`+`sqlite` activos a la vez), así que cada repository maneja
//! `Uuid`/`OffsetDateTime` a mano contra columnas `TEXT`.

use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::RepoError;

/// Mismo formato que `strftime('%Y-%m-%dT%H:%M:%fZ', 'now')` (el que usan
/// los `default` de las migraciones SQLite) — necesario para que comparar
/// por texto (`expires_at > strftime(..., 'now')`) coincida con el orden
/// cronológico real.
pub fn fmt_dt(dt: OffsetDateTime) -> String {
    let dt = dt.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        dt.year(),
        dt.month() as u8,
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second(),
        dt.millisecond(),
    )
}

pub fn parse_dt(valor: &str) -> Result<OffsetDateTime, RepoError> {
    OffsetDateTime::parse(valor, &time::format_description::well_known::Rfc3339)
        .map_err(|e| RepoError::Database(sqlx::Error::Decode(Box::new(e))))
}

pub fn parse_uuid(valor: &str) -> Result<Uuid, RepoError> {
    Uuid::parse_str(valor).map_err(|e| RepoError::Database(sqlx::Error::Decode(Box::new(e))))
}
