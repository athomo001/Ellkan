// Autor: Athan Espinoza

use time::OffsetDateTime;

#[derive(Debug, Clone)]
pub struct Preferencias {
    pub locale: String,
    pub theme: String,
    pub clipboard_clear_minutes: i32,
    pub auto_lock_minutes: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct Perfil {
    pub email: String,
    pub display_name: String,
    pub role: String,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub keys_created_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct Avatar {
    pub bytes: Vec<u8>,
    pub content_type: String,
}

/// Sólo el material que cambia al rotar la passphrase — las claves públicas
/// (`public_key_x25519`/`public_key_ed25519`) nunca cambian, no viajan acá.
#[derive(Debug, Clone)]
pub struct NuevaClavePrivada {
    pub encrypted_private_key_blob: Vec<u8>,
    pub private_key_nonce: Vec<u8>,
    pub kdf_salt: Vec<u8>,
}
