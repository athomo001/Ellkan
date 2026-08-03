// Autor: Athan Espinoza

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct CrearRolRequest {
    pub name: String,
    #[serde(default)]
    pub permissions: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ActualizarPermisosRequest {
    pub permissions: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct RolResponse {
    pub id: Uuid,
    pub name: String,
    pub permissions: Vec<String>,
    pub created_at: OffsetDateTime,
}
