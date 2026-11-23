// Autor: Athan Espinoza

use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

/// Tope de entradas de auditoría en una exportación (las más recientes).
pub const MAX_AUDITORIA: i64 = 10_000;

#[derive(Debug, Serialize)]
pub struct Cuenta {
    pub id: Uuid,
    pub email: String,
    pub display_name: String,
    pub role: Option<String>,
    pub active: bool,
    pub external_id: Option<String>,
    pub locale: String,
    pub theme: String,
    pub has_avatar: bool,
    #[serde(with = "time::serde::rfc3339::option")]
    pub email_verified_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
pub struct Grupo {
    pub name: String,
    pub is_admin: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub joined_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
pub struct Sesion {
    pub device: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_used_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub revoked_at: Option<OffsetDateTime>,
}

#[derive(Debug, Serialize)]
pub struct Dispositivo {
    pub label: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub first_seen_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_seen_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
pub struct Passkey {
    pub label: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_used_at: Option<OffsetDateTime>,
}

#[derive(Debug, Serialize)]
pub struct IdentidadSso {
    pub provider: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
pub struct ContactoEmergencia {
    /// `granter` si quien exporta es el titular; `grantee`, si es el contacto.
    pub role: String,
    pub other_email: String,
    pub status: String,
    pub wait_time_days: i32,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
pub struct EntradaAuditoria {
    pub event_type: String,
    pub subject_type: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
pub struct DatosPersonales {
    #[serde(with = "time::serde::rfc3339")]
    pub generated_at: OffsetDateTime,
    pub account: Cuenta,
    pub groups: Vec<Grupo>,
    pub sessions: Vec<Sesion>,
    pub known_devices: Vec<Dispositivo>,
    pub passkeys: Vec<Passkey>,
    pub totp_enabled: bool,
    pub sso_identities: Vec<IdentidadSso>,
    pub emergency_access: Vec<ContactoEmergencia>,
    pub audit_entries: Vec<EntradaAuditoria>,
    /// `true` si había más de `MAX_AUDITORIA` entradas (se dan las más recientes).
    pub audit_entries_truncated: bool,
    /// Lo que no está acá y por qué (ver `mod.rs`).
    pub not_included: &'static str,
}
