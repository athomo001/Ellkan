// Autor: Athan Espinoza

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Serialize)]
pub struct EstadoResponse {
    pub configured: bool,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub created_at: Option<OffsetDateTime>,
    pub must_rotate: bool,
}

/// `GET /me/recovery-kit/material` — el registro completo del kit propio,
/// para que la app de escritorio vinculada use el MISMO kit que el servidor
/// (misma identidad en los dos lados). Nada de esto es secreto sin la privada
/// del kit, que sólo tiene el usuario en el archivo que descargó.
#[derive(Debug, Serialize)]
pub struct MaterialKitResponse {
    pub kit_public_key_x25519_b64: String,
    pub sealed_identity_material_b64: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Pendiente #23: el sync app ↔ servidor la propaga — un kit usado para
    /// recuperar la cuenta en un lado tiene que quedar marcado en los dos.
    pub must_rotate: bool,
}

#[derive(Debug, Deserialize)]
pub struct GenerarRequest {
    pub kit_public_key_x25519_b64: String,
    pub sealed_identity_material_b64: String,
}

#[derive(Debug, Serialize)]
pub struct GenerarResponse {
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Deserialize)]
pub struct SolicitarResetRequest {
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct VerificarTokenResponse {
    pub sealed_identity_material_b64: String,
    /// `"totp"` | `"email"` — ver `recovery_kit::models::MetodoMfa`.
    pub mfa_method: &'static str,
    /// El cliente lo necesita como AAD para re-envolver la clave privada
    /// con la passphrase nueva — quien llega por el link directo nunca
    /// tipeó su email en ningún paso previo de la UI.
    pub email: String,
}

/// Mismos 3 campos que `NuevaClavePrivada` (`crate::me::models`) + el código
/// del segundo factor — el cliente ya desselló el material con la privada
/// del kit y lo re-selló contra una passphrase nueva antes de llamar acá.
#[derive(Debug, Deserialize)]
pub struct CompletarResetRequest {
    pub mfa_code: String,
    pub encrypted_private_key_blob_b64: String,
    pub private_key_nonce_b64: String,
    pub kdf_salt_b64: String,
    /// QA-03: parámetros de Argon2id del blob y `auth_key` del mismo Argon2id
    /// (los dos entran en la firma).
    pub kdf_params: ellkan_crypto::derivacion::ParametrosKdf,
    pub auth_key_b64: String,
    /// QA-06: nonce de `POST /auth/challenge` (un solo uso) y firma Ed25519
    /// de `ellkan_crypto::clave_privada::mensaje_reemplazo_clave_privada`
    /// sobre ese nonce y el blob nuevo — prueba de que quien lo sube tiene
    /// la identidad de la cuenta.
    pub challenge_nonce_b64: String,
    pub signature_b64: String,
}
