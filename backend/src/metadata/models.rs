// Autor: Athan Espinoza

use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct MetadataKey {
    pub id: Uuid,
    pub public_key_x25519: Vec<u8>,
    pub fingerprint: String,
    pub expired_at: Option<OffsetDateTime>,
    /// F-33: sólo tiene valor en la clave saliente de una rotación en curso.
    pub resources_pendientes_al_iniciar: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct MetadataKeyEnvelope {
    pub sealed_private_key: Vec<u8>,
}
