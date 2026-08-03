// Autor: Athan Espinoza

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct CrearTagRequest {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub is_shared: bool,
}

#[derive(Debug, Deserialize)]
pub struct ListarPorTagQuery {
    pub tag_id: Uuid,
}

#[derive(Debug, Serialize)]
pub struct TagResponse {
    pub id: Uuid,
    pub name: String,
    pub is_shared: bool,
    pub created_by: Uuid,
}
