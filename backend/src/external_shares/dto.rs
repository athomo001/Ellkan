// Autor: Athan Espinoza

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct CrearExternalShareRequest {
    pub ciphertext_b64: String,
    #[serde(default)]
    pub password_protected: bool,
    pub password_salt_b64: Option<String>,
    pub max_views: Option<i32>,
    pub expires_in_hours: i32,
}

#[derive(Debug, Serialize)]
pub struct ExternalShareCreadoResponse {
    pub id: Uuid,
    pub max_views: i32,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

/// Respuesta de `GET /external-shares/{id}` — jamás incluye la clave de
/// descifrado (viaja sólo en el fragmento de la URL, del lado cliente).
#[derive(Debug, Serialize)]
pub struct ExternalShareContenidoResponse {
    pub ciphertext_b64: String,
    pub password_protected: bool,
    pub password_salt_b64: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ExternalShareResumenResponse {
    pub id: Uuid,
    pub password_protected: bool,
    pub max_views: i32,
    pub view_count: i32,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub revoked_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub burned_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
pub struct ExternalSharePolicyResponse {
    pub enabled: bool,
    pub max_expiration_hours: i32,
    pub require_password: bool,
    pub allow_link: bool,
    pub allow_file: bool,
}

#[derive(Debug, Deserialize)]
pub struct ActualizarExternalSharePolicyRequest {
    pub enabled: bool,
    pub max_expiration_hours: i32,
    pub require_password: bool,
    pub allow_link: bool,
    pub allow_file: bool,
}
