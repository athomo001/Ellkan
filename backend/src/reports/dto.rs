// Autor: Athan Espinoza

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct ListarReporteQuery {
    pub cursor: Option<Uuid>,
    /// `inactive_users`/`resources_never_rotated`: umbral en días, default
    /// `90` si se omite (F-23, "parámetro de umbral configurable").
    pub days: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct PasswordExpiradoItem {
    pub user_id: Uuid,
    pub email: String,
    #[serde(with = "time::serde::rfc3339")]
    pub passphrase_set_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
pub struct MfaCoverageItem {
    pub user_id: Uuid,
    pub email: String,
    pub mfa_enabled: bool,
}

#[derive(Debug, Serialize)]
pub struct UsuarioInactivoItem {
    pub user_id: Uuid,
    pub email: String,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_login_at: Option<OffsetDateTime>,
}

#[derive(Debug, Serialize)]
pub struct RecursoSinRotarItem {
    pub resource_id: Uuid,
    pub created_by: Option<Uuid>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// `report_id` como discriminador serializado — cada variante ya trae el
/// shape de fila que le corresponde, ningún campo "vacío" según el tipo.
#[derive(Debug, Serialize)]
#[serde(tag = "report_id", rename_all = "snake_case")]
pub enum ReportResponse {
    PasswordsExpired { items: Vec<PasswordExpiradoItem>, next_cursor: Option<Uuid> },
    MfaCoverage { items: Vec<MfaCoverageItem>, next_cursor: Option<Uuid> },
    InactiveUsers { items: Vec<UsuarioInactivoItem>, next_cursor: Option<Uuid> },
    ResourcesNeverRotated { items: Vec<RecursoSinRotarItem>, next_cursor: Option<Uuid> },
}
