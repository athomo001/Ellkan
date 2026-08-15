// Autor: Athan Espinoza

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct CrearCarpetaRequest {
    pub id: Uuid,
    pub name_ciphertext_b64: String,
    pub name_nonce_b64: String,
    pub parent_folder_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
pub struct MoverCarpetaRequest {
    pub new_parent_folder_id: Option<Uuid>,
}

/// `grantee_type`: `"user"` (default histórico, campos `name_ciphertext_b64`/
/// `name_nonce_b64` sueltos) o `"group"` (2026-08-11, campo
/// `member_envelopes` — un nombre resellado por miembro actual del grupo,
/// el cliente ya los armó porque el servidor nunca puede resellar en
/// zero-knowledge).
#[derive(Debug, Deserialize)]
pub struct CompartirCarpetaRequest {
    #[serde(default = "grantee_type_default_user")]
    pub grantee_type: String,
    pub grantee_id: Uuid,
    pub level: String,
    #[serde(default)]
    pub name_ciphertext_b64: Option<String>,
    #[serde(default)]
    pub name_nonce_b64: Option<String>,
    #[serde(default)]
    pub member_envelopes: Vec<MiembroCarpetaEnvelope>,
}

fn grantee_type_default_user() -> String {
    "user".to_string()
}

#[derive(Debug, Deserialize)]
pub struct MiembroCarpetaEnvelope {
    pub user_id: Uuid,
    pub name_ciphertext_b64: String,
    pub name_nonce_b64: String,
}

#[derive(Debug, Serialize)]
pub struct NodoArbolResponse {
    pub folder_id: Uuid,
    pub parent_folder_id: Option<Uuid>,
    pub name_ciphertext_b64: String,
    pub name_nonce_b64: String,
    /// 2026-08-11: `Some(group_id)` si la carpeta está compartida con un
    /// grupo entero — el frontend lo usa para ofrecer el flujo de
    /// ceder/mantener al mover un recurso acá, y para saber que "todos los
    /// miembros pueden agregar" sin necesitar `update` individual.
    #[serde(default)]
    pub group_id: Option<Uuid>,
}
