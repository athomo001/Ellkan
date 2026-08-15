// Autor: Athan Espinoza

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct CrearGrupoRequest {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub parent_group_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
pub struct MoverGrupoRequest {
    pub new_parent_group_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
pub struct EnvelopeDto {
    pub resource_id: Uuid,
    pub sealed_dek_b64: String,
    pub secret_ciphertext_b64: String,
    pub secret_nonce_b64: String,
}

#[derive(Debug, Deserialize)]
pub struct AgregarMiembroRequest {
    #[serde(default)]
    pub is_admin: bool,
    #[serde(default)]
    pub envelopes: Vec<EnvelopeDto>,
}

#[derive(Debug, Deserialize)]
pub struct SetManagerRequest {
    pub is_admin: bool,
}

#[derive(Debug, Deserialize)]
pub struct ActualizarShareExemptRequest {
    pub exempt: bool,
}

#[derive(Debug, Serialize)]
pub struct GrupoResponse {
    pub id: Uuid,
    pub name: String,
    pub parent_group_id: Option<Uuid>,
    /// 2026-08-13 — ver `Group::share_exempt`.
    pub share_exempt: bool,
    /// Sólo poblado en `GET /groups/{id}` ("detalle + membresía completa",
    /// `03-api-contrato.md`) — vacío en listados (`GET /groups`,
    /// `GET /groups/{id}/subgroups`), que son sólo estructura del árbol.
    #[serde(default)]
    pub members: Vec<MiembroResponse>,
}

#[derive(Debug, Serialize)]
pub struct MiembroResponse {
    pub user_id: Uuid,
    pub is_admin: bool,
    pub email: String,
    pub display_name: String,
}
