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
    /// mismo comportamiento que Fase 0) — igual compartible (F-11/2026-08-11).
    /// Si se da, debe referenciar una metadata key compartida actualmente activa.
    #[serde(default)]
    pub metadata_key_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct RecursoResponse {
    pub id: Uuid,
    pub resource_type_id: Uuid,
    /// Parte C/2026-08-11: para que el cliente pueda armar el comando de
    /// conexión SSH/FTP/Telnet sin resolver `resource_type_id` aparte.
    pub resource_type_slug: String,
    pub metadata_ciphertext_b64: String,
    pub metadata_nonce_b64: String,
    pub created_by: Option<Uuid>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// F-30/F-07: refresco inteligente por foco de pestaña (`huboCambios`)
    /// y valor de `If-Match` al editar (concurrencia optimista).
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    pub metadata_key_type: String,
    pub metadata_key_id: Option<Uuid>,
    /// F-11: carpeta donde `auth.user_id` tiene posicionado este recurso en
    /// su propio árbol — `None` = raíz. Sólo se completa en `listar`
    /// (`GET /resources`, que ya calcula el mapa completo para el filtro
    /// `?folder_id=`); en el resto de los handlers queda `None` a propósito,
    /// no vale la pena la consulta extra para un solo recurso.
    #[serde(default)]
    pub folder_id: Option<Uuid>,
}

/// `GET /resources/{id}/recipients` (F-07).
#[derive(Debug, Serialize)]
pub struct DestinatarioResponse {
    pub user_id: Uuid,
    pub public_key_x25519_b64: String,
}

#[derive(Debug, Deserialize)]
pub struct EnvelopeInputRequest {
    pub recipient_user_id: Uuid,
    pub sealed_dek_b64: String,
    pub secret_ciphertext_b64: String,
    pub secret_nonce_b64: String,
}

/// `PUT /resources/{id}` (F-07) — el header `If-Match` (no el body) lleva
/// el `updated_at` esperado, mismo criterio HTTP estándar que la spec pide.
#[derive(Debug, Deserialize)]
pub struct ActualizarRecursoRequest {
    pub metadata_ciphertext_b64: String,
    pub metadata_nonce_b64: String,
    pub envelopes: Vec<EnvelopeInputRequest>,
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

/// `GET /resources?tag_id=...&folder_id=...` — extensión de F-10/F-11 sobre
/// el listado ya existente (`03-api-contrato.md`: "filtros por carpeta/tag").
#[derive(Debug, Deserialize, Default)]
pub struct ListarQuery {
    pub tag_id: Option<Uuid>,
    pub folder_id: Option<Uuid>,
}

/// `PUT /resources/{id}/move` (F-11) — `folder_id: None` saca el recurso de
/// cualquier carpeta (vuelve a la raíz del árbol propio).
#[derive(Debug, Deserialize)]
pub struct MoverRecursoRequest {
    pub folder_id: Option<Uuid>,
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

/// Módulo 3 (compartir en lote): mismo shape que `CompartirRequest` por
/// ítem, repetido — el cliente ya hizo N×M sellados asimétricos
/// client-side (uno por par recurso×destinatario, mismo costo barato que un
/// share individual), esto sólo los agrupa en una sola llamada de red.
#[derive(Debug, Deserialize)]
pub struct CompartirLoteItem {
    pub resource_id: Uuid,
    pub recipient_user_id: Uuid,
    pub sealed_dek_b64: String,
    pub secret_ciphertext_b64: String,
    pub secret_nonce_b64: String,
    #[serde(default)]
    pub level: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CompartirLoteRequest {
    pub items: Vec<CompartirLoteItem>,
}

/// Tolerante a fallos parciales — mismo criterio que la carga CSV de
/// grupos (Bloque C): un ítem inválido (ej. el caller no es `owner` de ese
/// recurso puntual) no debería abortar los demás ítems del lote.
#[derive(Debug, Serialize)]
pub struct CompartirLoteItemResultado {
    pub resource_id: Uuid,
    pub recipient_user_id: Uuid,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CompartirLoteResponse {
    pub resultados: Vec<CompartirLoteItemResultado>,
}

#[derive(Debug, Serialize)]
pub struct PermisoGranteeResponse {
    pub grantee_type: String,
    pub grantee_id: Uuid,
    pub level: String,
    pub label: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CambiarNivelRequest {
    pub level: String,
}
