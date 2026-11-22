// Autor: Athan Espinoza

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct PreferenciasResponse {
    pub locale: String,
    pub theme: String,
    pub clipboard_clear_minutes: i32,
    pub auto_lock_minutes: Option<i32>,
}

#[derive(Debug, Serialize)]
pub struct GrupoDeUsuarioResponse {
    pub group_id: Uuid,
    pub name: String,
    pub is_admin: bool,
}

#[derive(Debug, Deserialize)]
pub struct ActualizarPreferenciasRequest {
    pub locale: String,
    pub theme: String,
    pub clipboard_clear_minutes: i32,
    pub auto_lock_minutes: Option<i32>,
}

#[derive(Debug, Serialize)]
pub struct PerfilResponse {
    /// 2026-08-15: antes no se exponía (el extractor ya lo conoce por
    /// sesión) — la extensión lo necesita del lado cliente para el AAD
    /// `resource_id||created_by` al crear un recurso tras un login que pasó
    /// por MFA (`POST /auth/mfa/verify` no devuelve `user_id`, a propósito,
    /// mismo criterio de "un solo par de campos relevante" que `/auth/verify`).
    pub id: Uuid,
    pub email: String,
    pub display_name: String,
    pub role: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub keys_created_at: OffsetDateTime,
    /// Pendiente #133: cuenta creada por SSO sin claves todavía.
    pub needs_key_enrollment: bool,
}

/// Pendiente #133: `POST /me/keys/enroll`, mismo armado que el registro.
#[derive(Debug, Deserialize)]
pub struct EnrolarClavesRequest {
    pub public_key_x25519_b64: String,
    pub public_key_ed25519_b64: String,
    pub encrypted_private_key_blob_b64: String,
    pub private_key_nonce_b64: String,
    pub kdf_salt_b64: String,
}

#[derive(Debug, Deserialize)]
pub struct ActualizarAvatarRequest {
    pub avatar_b64: String,
    pub content_type: String,
}

#[derive(Debug, Deserialize)]
pub struct CambiarPassphraseRequest {
    pub encrypted_private_key_blob_b64: String,
    pub private_key_nonce_b64: String,
    pub kdf_salt_b64: String,
    /// QA-06: nonce de `POST /auth/challenge` (un solo uso) y firma Ed25519
    /// de `ellkan_crypto::clave_privada::mensaje_reemplazo_clave_privada`
    /// sobre ese nonce y el blob nuevo — prueba de que quien lo sube tiene
    /// la identidad de la cuenta.
    pub challenge_nonce_b64: String,
    pub signature_b64: String,
}
