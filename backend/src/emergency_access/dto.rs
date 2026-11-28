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

/// F-36 (#134): `GET /me/emergency-access/{id}/vault`.
#[derive(Debug, Serialize)]
pub struct BovedaTitularResponse {
    pub granter_id: Uuid,
    pub granter: PersonaResponse,
    pub access_level: String,
    /// Las privadas del titular selladas para el contacto (lo mismo que en
    /// el listado), para no depender de otra llamada.
    pub sealed_material_b64: String,
    pub resources: Vec<RecursoTitularResponse>,
}

#[derive(Debug, Serialize)]
pub struct RecursoTitularResponse {
    pub id: Uuid,
    pub created_by: Option<Uuid>,
    pub resource_type_slug: String,
    pub metadata_ciphertext_b64: String,
    pub metadata_nonce_b64: String,
    pub metadata_key_type: String,
    pub metadata_key_id: Option<Uuid>,
    pub metadata_sealed_key_b64: Option<String>,
    pub sealed_dek_b64: String,
    pub secret_ciphertext_b64: String,
    pub secret_nonce_b64: String,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}
