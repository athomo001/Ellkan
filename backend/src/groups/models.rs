// Autor: Athan Espinoza

use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Group {
    pub id: Uuid,
    pub name: String,
    pub parent_group_id: Option<Uuid>,
}

#[derive(Debug, Clone)]
pub struct Miembro {
    pub user_id: Uuid,
    pub is_admin: bool,
}

/// Un envelope de secreto ya sellado por el caller para un recurso que el
/// grupo ya tiene compartido — ver `GroupService::agregar_miembro`.
#[derive(Debug, Clone)]
pub struct EnvelopeParaMiembroNuevo {
    pub resource_id: Uuid,
    pub sealed_dek: Vec<u8>,
    pub secret_ciphertext: Vec<u8>,
    pub secret_nonce: Vec<u8>,
}
