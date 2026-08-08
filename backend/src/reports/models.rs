// Autor: Athan Espinoza

use time::OffsetDateTime;
use uuid::Uuid;

/// Enum cerrado — `reportId` fuera de estos cuatro valores es `404`, nunca
/// un reporte vacío (criterio de aceptación literal de F-23).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportId {
    PasswordsExpired,
    MfaCoverage,
    InactiveUsers,
    ResourcesNeverRotated,
}

impl ReportId {
    pub fn from_slug(s: &str) -> Option<Self> {
        Some(match s {
            "passwords_expired" => ReportId::PasswordsExpired,
            "mfa_coverage" => ReportId::MfaCoverage,
            "inactive_users" => ReportId::InactiveUsers,
            "resources_never_rotated" => ReportId::ResourcesNeverRotated,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone)]
pub struct FilaPasswordExpirado {
    pub user_id: Uuid,
    pub email: String,
    /// **No hay rotación de passphrase implementada todavía (F-15)** — no
    /// existe ninguna columna "passphrase cambiada por última vez" en el
    /// schema, porque nunca se escribe. Se usa `user_keys.created_at` como
    /// la única fecha real disponible que se acerca al concepto: hoy
    /// equivale siempre a la fecha de alta de la cuenta, documentado acá y
    /// en la respuesta — no se inventa un timestamp que no existe.
    pub passphrase_set_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct FilaMfaCoverage {
    pub user_id: Uuid,
    pub email: String,
    /// F-14 (TOTP de login) únicamente — passkeys (F-03) no cuentan acá,
    /// la spec cita expresamente "(F-14)" para este reporte.
    pub mfa_enabled: bool,
}

#[derive(Debug, Clone)]
pub struct FilaUsuarioInactivo {
    pub user_id: Uuid,
    pub email: String,
    pub last_login_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone)]
pub struct FilaRecursoSinRotar {
    pub resource_id: Uuid,
    pub created_by: Option<Uuid>,
    pub created_at: OffsetDateTime,
}
