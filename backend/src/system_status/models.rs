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
    /// F-03: `ELLKAN_RP_ORIGIN` sigue en el default de desarrollo
    /// (`http://localhost:8080`) o no es `https://` — mismo chequeo que ya
    /// documenta `state.rs::construir_webauthn` como obligatorio en
    /// producción (con el default, cualquier origin se acepta como
    /// "localhost", WebAuthn pierde su propiedad anti-phishing). Desde
    /// spec/11 (operativa 1, 2026-08-10) Ellkan sí puede terminar TLS él
    /// mismo (`ELLKAN_TLS_CERT_FILE`/`ELLKAN_TLS_KEY_FILE`, `main.rs` vía
    /// `axum-server`+`rustls`) además de la opción de un reverse proxy
    /// delante — pero este chequeo no inspecciona ninguno de los dos casos
    /// puntualmente (no lee el cert propio ni sabe si hay un proxy),
    /// `ELLKAN_RP_ORIGIN` en `https://` sigue siendo la señal indirecta más
    /// cercana a "TLS configurado" que el servidor puede verificar solo.
    OrigenSeguro { nivel: NivelCheck, origen: String },
    /// Hallazgo real de uso: la página nunca respondía "¿hay al menos un
    /// admin activo?" — la pregunta más básica de todas.
    AdminsActivos { nivel: NivelCheck, cantidad: i64 },
    /// Operativa 1 (spec/11, 2026-08-10): TLS terminado por el propio
    /// binario (`ELLKAN_TLS_CERT_FILE`/`ELLKAN_TLS_KEY_FILE`) — señal
    /// directa, a diferencia de `OrigenSeguro` que sólo infiere por el
    /// origin configurado (también aplica si hay un reverse proxy
    /// delante, que este check no puede ver).
    TlsInProcess { nivel: NivelCheck, activo: bool },
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct GrupoChecks {
    pub categoria: &'static str,
    pub checks: Vec<Check>,
}
