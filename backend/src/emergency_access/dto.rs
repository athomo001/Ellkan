// Autor: Athan Espinoza

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct EmergencyAccessPolicyResponse {
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct ActualizarPoliticaRequest {
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct DesignarRequest {
    pub grantee_id: Uuid,
    pub access_level: String,
    pub sealed_material_b64: String,
    pub wait_time_days: i32,
}

#[derive(Debug, Serialize, Default)]
pub struct PersonaResponse {
    pub email: String,
    pub display_name: String,
}

#[derive(Debug, Serialize)]
pub struct EmergencyAccessResponse {
    pub id: Uuid,
    pub granter_id: Uuid,
    pub grantee_id: Uuid,
    /// Pendiente #131: quién es el titular y quién el contacto.
    pub granter: PersonaResponse,
    pub grantee: PersonaResponse,
    pub access_level: String,
    pub wait_time_days: i32,
    pub status: String,
    pub request_status: Option<String>,
    pub sealed_material_b64: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}
