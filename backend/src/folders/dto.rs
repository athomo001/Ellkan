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

#[derive(Debug, Serialize)]
pub struct NodoArbolResponse {
    pub folder_id: Uuid,
    pub parent_folder_id: Option<Uuid>,
    pub name_ciphertext_b64: String,
    pub name_nonce_b64: String,
}
