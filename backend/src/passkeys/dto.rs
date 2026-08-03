// Autor: Athan Espinoza

use serde::{Deserialize, Serialize};
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
}
