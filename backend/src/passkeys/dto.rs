// Autor: Athan Espinoza

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

/// El propio tipo de `webauthn-rs` ya es el formato de wire estándar que el
/// cliente (navegador real, o `SoftPasskey` en tests) produce — no hace
/// falta envolverlo en un DTO propio, sólo agregar los campos que Ellkan
/// necesita además de la ceremonia en sí.
#[derive(Debug, Deserialize)]
pub struct FinalizarRegistroRequest {
    pub credential: RegisterPublicKeyCredential,
    /// Nullable a propósito (F-03): el cliente sólo lo manda si el
    /// autenticador soportó la extensión PRF — el servidor nunca la calcula
    /// ni la valida, sólo guarda el blob opaco.
    #[serde(default)]
    pub prf_wrapped_private_key_b64: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct IniciarAutenticacionRequest {
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct FinalizarAutenticacionRequest {
    pub email: String,
    pub credential: PublicKeyCredential,
}

#[derive(Debug, Serialize)]
pub struct SesionWebauthnResponse {
    pub session_id: Uuid,
    pub user_id: Uuid,
    /// F-03 (PRF): presente sólo si esta passkey se registró con PRF — el
    /// cliente lo usa para desenvolver la passphrase localmente y saltear el
    /// prompt manual. `None` para toda passkey registrada en la rama "sin
    /// PRF" (comportamiento sin cambios).
    pub prf_wrapped_private_key_b64: Option<String>,
}

/// F-03 (PRF): listado de passkeys propias (`GET /me/passkeys`) — nunca
/// expone `passkey_data`/`credential_id` (material de la ceremonia
/// WebAuthn, sin valor para el usuario y sin motivo para viajar dos veces).
#[derive(Debug, Serialize)]
pub struct PasskeyResponse {
    pub id: Uuid,
    pub label: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_used_at: Option<OffsetDateTime>,
    pub tiene_prf: bool,
}
