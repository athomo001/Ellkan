// Autor: Athan Espinoza

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Serialize)]
pub struct MfaPolicyResponse {
    pub require_mfa: bool,
    pub allowed_methods: Vec<String>,
    pub grace_period_days: i32,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub require_mfa_since: Option<OffsetDateTime>,
}

#[derive(Debug, Deserialize)]
pub struct ActualizarMfaPolicyRequest {
    pub require_mfa: bool,
    pub allowed_methods: Vec<String>,
    pub grace_period_days: i32,
}

/// `POST /me/mfa/totp/setup` — el secreto en claro y el URI `otpauth://`
/// (para QR) se devuelven **una sola vez**; tras esta respuesta, sólo la
/// forma cifrada queda en la base.
#[derive(Debug, Serialize)]
pub struct SetupTotpResponse {
    pub secret_base32: String,
    pub otpauth_uri: String,
}

#[derive(Debug, Deserialize)]
pub struct ConfirmarTotpRequest {
    pub code: String,
}

#[derive(Debug, Deserialize)]
pub struct VerificarMfaRequest {
    pub code: String,
}
