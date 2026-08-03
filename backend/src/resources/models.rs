// Autor: Athan Espinoza

use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Resource {
    pub id: Uuid,
    pub resource_type_id: Uuid,
    pub metadata_ciphertext: Vec<u8>,
    pub metadata_nonce: Vec<u8>,
    pub created_by: Uuid,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct SecretEnvelope {
    pub sealed_dek: Vec<u8>,
    pub secret_ciphertext: Vec<u8>,
    pub secret_nonce: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NivelPermiso {
    Read,
    Update,
    Owner,
}

impl NivelPermiso {
    pub fn as_db_str(self) -> &'static str {
        match self {
            NivelPermiso::Read => "read",
            NivelPermiso::Update => "update",
            NivelPermiso::Owner => "owner",
        }
    }
}
