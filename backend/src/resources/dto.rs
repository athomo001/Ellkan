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
}

#[derive(Debug, Serialize)]
pub struct RecursoResponse {
    pub id: Uuid,
    pub resource_type_id: Uuid,
    pub metadata_ciphertext_b64: String,
    pub metadata_nonce_b64: String,
    pub created_by: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
pub struct SecretoResponse {
    pub sealed_dek_b64: String,
    pub secret_ciphertext_b64: String,
    pub secret_nonce_b64: String,
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
