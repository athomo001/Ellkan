// Autor: Athan Espinoza

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct SsoConfigResponse {
    pub issuer_url: Option<String>,
    pub client_id: Option<String>,
    pub jit_provisioning_enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct ActualizarSsoConfigRequest {
    pub issuer_url: Option<String>,
    pub client_id: Option<String>,
    pub jit_provisioning_enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: String,
    pub state: String,
}

/// F-17: un login SSO nunca pasa por F-02 (verificación de dispositivo
/// nuevo) — el propio IdP ya autenticó la identidad de forma más fuerte que
/// un código emailado, mismo criterio ya usado para login con passkey
/// (F-03, "se considera equivalente a MFA activo"). Sí sigue pasando por
/// F-14 (MFA de Ellkan) si la política lo exige.
#[derive(Debug, Serialize)]
pub struct LoginCompletoResponse {
    pub estado: String,
    pub session_id: Option<uuid::Uuid>,
}
