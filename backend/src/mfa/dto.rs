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
    /// 2026-08-13: recién configurado el segundo factor en este dispositivo
    /// puntual — cuenta como "ya verificado" acá también, ver
    /// `VerificarMfaRequest`. `Option` para no romper callers viejos que
    /// todavía no lo mandan (no hay downside: sin esto, simplemente no se
    /// recuerda el dispositivo, mismo comportamiento que antes de F-14b).
    #[serde(default)]
    pub device_token_hash_b64: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct VerificarMfaRequest {
    pub code: String,
    /// 2026-08-13: mismo hash que `/auth/verify` — permite recordar que MFA
    /// ya se pasó en este dispositivo puntual (ver `KnownDeviceRepository`).
    /// `Option` por la misma razón que `ConfirmarTotpRequest`.
    #[serde(default)]
    pub device_token_hash_b64: Option<String>,
}
