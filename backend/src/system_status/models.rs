// Autor: Athan Espinoza

use time::OffsetDateTime;

/// Semáforo del check — el frontend decide color/ícono a partir de esto,
/// nunca del texto libre (no hay texto libre acá, ver `Check`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NivelCheck {
    Ok,
    Advertencia,
    Error,
}

/// Enum cerrado, un `id` fijo por check — mismo criterio que `ReportId`
/// (`reports/models.rs`): el frontend mapea `id` a un texto traducido
/// (es/en, F-31) y a los parámetros de cada variante, nunca el backend
/// manda una oración ya armada (rompería el idioma elegido por el usuario).
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "id", rename_all = "snake_case")]
pub enum Check {
    VersionApp { nivel: NivelCheck, version: String },
    DbPing { nivel: NivelCheck },
    DbMigraciones { nivel: NivelCheck, aplicadas: i64, fallidas: i64 },
    SmtpConfigurado { nivel: NivelCheck, configurado: bool },
    CorreoBacklog { nivel: NivelCheck, pendientes: i64, fallidos: i64 },
    SsoConfigurado { nivel: NivelCheck, configurado: bool },
    DirectorySyncConfigurado {
        nivel: NivelCheck,
        configurado: bool,
        #[serde(with = "time::serde::rfc3339::option")]
        ultima_sincronizacion: Option<OffsetDateTime>,
    },
    MetadataKeyRotacion { nivel: NivelCheck, claves_activas: i64 },
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct GrupoChecks {
    pub categoria: &'static str,
    pub checks: Vec<Check>,
}
