// Autor: Athan Espinoza

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct AuditLogQuery {
    pub cursor: Option<Uuid>,
    pub limit: Option<i64>,
    pub actor_user_id: Option<Uuid>,
    pub event_type: Option<String>,
    /// El derive `Deserialize` liso de `OffsetDateTime` usa un formato
    /// interno no legible por humanos, no ISO 8601 — `time::serde::rfc3339`
    /// es el módulo que sí acepta la cadena que un cliente HTTP real manda
    /// en un query param (mismo criterio que `RecursoResponse.created_at`
    /// para el sentido inverso, serialización).
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub from: Option<OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub to: Option<OffsetDateTime>,
}

#[derive(Debug, Deserialize)]
pub struct AuditLogExportQuery {
    pub actor_user_id: Option<Uuid>,
    pub event_type: Option<String>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub from: Option<OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub to: Option<OffsetDateTime>,
    /// `ndjson` (default) o `csv` — F-13, `03-api-contrato.md`.
    pub format: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuditLogEntryResponse {
    pub id: Uuid,
    pub actor_user_id: Option<Uuid>,
    pub event_type: String,
    pub subject_type: Option<String>,
    pub subject_id: Option<Uuid>,
    pub metadata: Value,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
pub struct AuditLogPageResponse {
    pub items: Vec<AuditLogEntryResponse>,
    pub next_cursor: Option<Uuid>,
}
