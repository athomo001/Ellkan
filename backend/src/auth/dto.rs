// Autor: Athan Espinoza

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub display_name: String,
    pub public_key_x25519_b64: String,
    pub public_key_ed25519_b64: String,
    pub encrypted_private_key_blob_b64: String,
    pub private_key_nonce_b64: String,
    pub kdf_salt_b64: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub user_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct ServerKeyResponse {
    pub public_key_ed25519_b64: String,
}

#[derive(Debug, Deserialize)]
pub struct ChallengeRequest {
    pub email: String,
}

/// F-01 (frontend web) — no está en `03-api-contrato.md`, documentado igual
/// que `rekey-metadata`/`device-approval` en fases anteriores: sin este
/// endpoint, un navegador sin estado local no tiene forma de desbloquear su
/// propia clave privada al loguearse (la CLI lo evita cacheando el blob en
/// un perfil local tras registrarse, un navegador no tiene ese cache).
#[derive(Debug, Deserialize)]
pub struct KeyMaterialRequest {
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct KeyMaterialResponse {
    pub encrypted_private_key_blob_b64: String,
    pub private_key_nonce_b64: String,
    pub kdf_salt_b64: String,
}

#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    pub nonce_b64: String,
}

#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    pub email: String,
    pub nonce_b64: String,
    pub signature_b64: String,
    /// Hash del token de dispositivo persistente del cliente (F-02) — nunca
    /// el token en claro, y nunca un User-Agent.
    pub device_token_hash_b64: String,
}

/// `estado` es `"completo"` (con `session_id`/`user_id`), `"pendiente_dispositivo"`
/// (con `device_challenge_id`), `"pendiente_mfa"` (con `session_id` de una
/// sesión parcial, F-14 — el cliente lo usa como Bearer contra
/// `POST /auth/mfa/verify`) o `"requiere_configurar_mfa"` (mismo
/// `session_id` parcial, pero contra `POST /me/mfa/totp/setup`) — nunca más
/// de un par de campos relevante a la vez. Mismo shape para `POST
/// /auth/verify` y `POST /auth/verify-device`: los dos pueden resolver en
/// cualquiera de estos cuatro estados desde que existe F-14.
#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    pub estado: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_challenge_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
pub struct VerifyDeviceRequest {
    pub device_challenge_id: Uuid,
    pub code: String,
}

#[derive(Debug, Serialize)]
pub struct PublicKeyResponse {
    pub user_id: Uuid,
    pub public_key_x25519_b64: String,
}
