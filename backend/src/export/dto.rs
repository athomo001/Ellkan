// Autor: Athan Espinoza

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct ExportPolicyResponse {
    pub export_enabled: bool,
    pub allowed_formats: Vec<String>,
    pub import_enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct ActualizarExportPolicyRequest {
    pub export_enabled: bool,
    pub allowed_formats: Vec<String>,
    pub import_enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct ReportarExportEventRequest {
    /// `"export"` o `"import"` — cualquier otro valor es `INVALID_INPUT`.
    pub event_type: String,
    /// `"kdbx"`/`"csv"`/`"cxf"` — validado contra `allowed_formats`.
    pub format: String,
    pub resource_count: i32,
}

#[derive(Debug, Deserialize)]
pub struct FormatoExportQuery {
    /// `ndjson` (default) o `csv` — mismo contrato que `GET /admin/audit-log/export`.
    pub format: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UsuarioExportResponse {
    pub id: Uuid,
    pub email: String,
    pub display_name: String,
    pub role: String,
    pub active: bool,
    #[serde(with = "time::serde::rfc3339::option")]
    pub deleted_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    pub mfa_configured: bool,
    pub passkey_count: i64,
    pub groups: Vec<String>,
    pub public_key_x25519_b64: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MiembroDeGrupoResponse {
    pub user_id: Uuid,
    pub is_admin: bool,
}

#[derive(Debug, Serialize)]
pub struct GrupoExportResponse {
    pub id: Uuid,
    pub name: String,
    pub parent_group_id: Option<Uuid>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub deleted_at: Option<OffsetDateTime>,
    pub members: Vec<MiembroDeGrupoResponse>,
}
