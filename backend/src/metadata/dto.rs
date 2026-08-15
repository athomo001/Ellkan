// Autor: Athan Espinoza

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct DestinatarioEnvelope {
    pub user_id: Uuid,
    pub sealed_private_key_b64: String,
}

#[derive(Debug, Deserialize)]
pub struct AgregarDestinatarioRequest {
    pub user_id: Uuid,
    pub sealed_private_key_b64: String,
}

#[derive(Debug, Deserialize)]
pub struct CrearMetadataKeyRequest {
    pub id: Uuid,
    pub public_key_x25519_b64: String,
    pub fingerprint: String,
    #[serde(default)]
    pub destinatarios: Vec<DestinatarioEnvelope>,
}

#[derive(Debug, Serialize)]
pub struct RotationStatusResponse {
    pub activa: bool,
    pub saliente_id: Option<Uuid>,
    pub entrante_id: Option<Uuid>,
    pub total_al_iniciar: Option<i32>,
    pub pendientes: Option<i64>,
}

/// El fingerprint viaja siempre en la misma forma en cada respuesta — es la
/// pieza que el cliente pinea la primera vez (TOFU) y compara después; el
/// servidor no hace nada más que servirlo consistentemente.
#[derive(Debug, Serialize)]
pub struct MetadataKeyResponse {
    pub id: Uuid,
    pub public_key_x25519_b64: String,
    pub fingerprint: String,
    #[serde(with = "time::serde::rfc3339::option")]
    pub expired_at: Option<OffsetDateTime>,
    pub own_sealed_private_key_b64: Option<String>,
}
