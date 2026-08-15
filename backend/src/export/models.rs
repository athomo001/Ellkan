// Autor: Athan Espinoza

use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ExportPolicy {
    pub export_enabled: bool,
    pub allowed_formats: Vec<String>,
    pub import_enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TipoEventoExport {
    Export,
    Import,
}

/// Fila de `GET /admin/users/export` (F-29) — proyección de lectura, nunca
/// persistida. Exclusión dura a nivel de tipo: no hay ningún campo acá que
/// pueda llevar `encrypted_private_key_blob`/`kdf_salt`/credenciales — esos
/// campos no existen en este struct, no es un filtro en runtime.
#[derive(Debug, Clone)]
pub struct FilaExportUsuario {
    pub id: Uuid,
    pub email: String,
    pub display_name: String,
    pub role: String,
    pub active: bool,
    pub deleted_at: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub mfa_configured: bool,
    pub passkey_count: i64,
    pub groups: Vec<String>,
    /// F-29: "si el caso de uso es migración real... se puede incluir la
    /// clave **pública** de `user_keys` (nunca la privada)". `None` sólo
    /// debería pasar si el usuario nunca terminó el registro (sin fila en
    /// `user_keys`), estado transitorio/anómalo, no el caso normal.
    pub public_key_x25519_b64: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MiembroDeGrupoExport {
    pub user_id: Uuid,
    pub is_admin: bool,
}

/// Fila de `GET /admin/groups/export` (F-29).
#[derive(Debug, Clone)]
pub struct FilaExportGrupo {
    pub id: Uuid,
    pub name: String,
    pub parent_group_id: Option<Uuid>,
    pub deleted_at: Option<OffsetDateTime>,
    pub members: Vec<MiembroDeGrupoExport>,
}
