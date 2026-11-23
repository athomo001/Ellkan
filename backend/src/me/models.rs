// Autor: Athan Espinoza

use ellkan_crypto::derivacion::ParametrosKdf;

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
    /// Pendiente #133: cuenta creada por SSO que todavía no tiene claves
    /// (el blob de la privada está vacío).
    pub necesita_enrolar_claves: bool,
}

/// Pendiente #133: el primer par de claves de una cuenta creada por SSO.
#[derive(Debug, Clone)]
pub struct ClavesIniciales {
    pub public_key_x25519: Vec<u8>,
    pub public_key_ed25519: Vec<u8>,
    pub encrypted_private_key_blob: Vec<u8>,
    pub private_key_nonce: Vec<u8>,
    pub kdf_salt: Vec<u8>,
    /// QA-03: parámetros de Argon2id y `auth_key` del mismo Argon2id.
    pub kdf_params: ParametrosKdf,
    pub auth_key: Vec<u8>,
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
    /// QA-03: parámetros de Argon2id con que se selló el blob nuevo.
    pub kdf_params: ParametrosKdf,
    /// QA-03: `auth_key` del mismo Argon2id. Entra en la firma de la prueba
    /// de posesión y se guarda sólo su verificador.
    pub auth_key: Vec<u8>,
}

impl NuevaClavePrivada {
    /// QA-03: lo que se guarda en `user_keys.auth_verifier`.
    pub fn auth_verifier(&self) -> Vec<u8> {
        ellkan_crypto::derivacion::verificador_auth(&self.auth_key).to_vec()
    }
}

impl ClavesIniciales {
    /// QA-03: lo que se guarda en `user_keys.auth_verifier`.
    pub fn auth_verifier(&self) -> Vec<u8> {
        ellkan_crypto::derivacion::verificador_auth(&self.auth_key).to_vec()
    }
}
