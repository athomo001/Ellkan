// Autor: Athan Espinoza

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct CrearRecursoRequest {
    /// Generado client-side (UUIDv7) — el AAD del AEAD (`resource_id` +
    /// `created_by`) se fija antes de cifrar, así que el cliente necesita
    /// conocer el id del recurso antes de que exista la fila.
    pub id: Uuid,
    pub resource_type_slug: String,
    pub metadata_ciphertext_b64: String,
    pub metadata_nonce_b64: String,
    pub sealed_dek_b64: String,
    pub secret_ciphertext_b64: String,
    pub secret_nonce_b64: String,
    /// F-06 completo: si se omite, el recurso queda `user_key` (personal,
    /// no compartible) — mismo comportamiento que Fase 0. Si se da, debe
    /// referenciar una metadata key compartida actualmente activa.
    #[serde(default)]
    pub metadata_key_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct RecursoResponse {
    pub id: Uuid,
    pub resource_type_id: Uuid,
    pub metadata_ciphertext_b64: String,
    pub metadata_nonce_b64: String,
    pub created_by: Option<Uuid>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    pub metadata_key_type: String,
    pub metadata_key_id: Option<Uuid>,
}

/// F-08 — nunca un código generado, sólo si el tipo de recurso declara TOTP.
#[derive(Debug, Serialize)]
pub struct TotpResponse {
    pub tiene_totp: bool,
}

#[derive(Debug, Serialize)]
pub struct SecretoResponse {
    pub sealed_dek_b64: String,
    pub secret_ciphertext_b64: String,
    pub secret_nonce_b64: String,
}

/// `GET /resources?tag_id=...` — extensión de F-10 sobre el listado ya
/// existente (`03-api-contrato.md`: "filtros por carpeta/tag").
#[derive(Debug, Deserialize, Default)]
pub struct ListarQuery {
    pub tag_id: Option<Uuid>,
}

/// `POST /resources/{id}/rekey-metadata` — F-33, endpoint nuevo no listado
/// en el inventario original de `03-api-contrato.md`: sin él, la migración
/// de metadata durante una rotación no tiene ningún mecanismo real por el
/// que un cliente pueda ejecutarla (el servidor nunca ve la metadata en
/// claro, así que no puede re-envolverla él mismo).
#[derive(Debug, Deserialize)]
pub struct RekeyMetadataRequest {
    pub expected_current_metadata_key_id: Uuid,
    pub new_metadata_key_id: Uuid,
    pub metadata_ciphertext_b64: String,
    pub metadata_nonce_b64: String,
}

#[derive(Debug, Deserialize)]
pub struct CompartirRequest {
    pub recipient_user_id: Uuid,
    pub sealed_dek_b64: String,
    pub secret_ciphertext_b64: String,
    pub secret_nonce_b64: String,
    /// `read` | `update` | `owner` — default `read` si se omite.
    #[serde(default)]
    pub level: Option<String>,
}
