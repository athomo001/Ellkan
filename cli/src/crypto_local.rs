// Autor: Athan Espinoza

//! Helpers propios de la CLI que combinan `ellkan-crypto` — generar el
//! keypair de registro, reconstruir la clave privada bajo demanda (nunca
//! cacheada ya descifrada), y cifrar/descifrar metadata+secreto de un
//! recurso.

use ed25519_dalek::{Signer, SigningKey};
use secrecy::SecretBox;
use x25519_dalek::StaticSecret;
use zeroize::Zeroize;

use ellkan_crypto::aead::{self, Envoltura};
use ellkan_crypto::claves::{KeypairAcuerdo, KeypairFirma};
use ellkan_crypto::clave_privada::{self, EncryptedPrivateKeyBlob};
use ellkan_crypto::secretos::{ClaveSecreta32, PassphraseSecreta};
use ellkan_crypto::sellado;

pub struct NuevoKeypar {
    pub x25519: KeypairAcuerdo,
    pub ed25519: KeypairFirma,
}

impl NuevoKeypar {
    pub fn generar() -> Self {
        Self { x25519: KeypairAcuerdo::generar(), ed25519: KeypairFirma::generar() }
    }

    /// X25519 privada (32) || Ed25519 privada (32) — un solo blob de 64
    /// bytes, cifrado como una unidad (`user_keys.encrypted_private_key_blob`).
    fn concatenar_privadas(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(self.x25519.privada().to_bytes().as_slice());
        buf[32..].copy_from_slice(&self.ed25519.firmante().to_bytes());
        buf
    }
}

pub fn cifrar_para_registro(
    keypar: &NuevoKeypar,
    passphrase: &PassphraseSecreta,
    email: &str,
) -> Result<EncryptedPrivateKeyBlob, ellkan_crypto::clave_privada::ErrorClavePrivada> {
    let salt: [u8; 16] = ellkan_crypto::aleatoriedad::bytes_aleatorios();
    let mut privadas = keypar.concatenar_privadas();
    let blob = clave_privada::cifrar_clave_privada(passphrase, salt, &privadas, email.as_bytes())?;
    privadas.zeroize();
    Ok(blob)
}

/// Reconstruye la clave privada desde el blob cifrado — sólo para el
/// instante de uso, nunca se cachea descifrada.
pub struct ClavePrivadaReconstruida {
    pub x25519: StaticSecret,
    signing_key: SigningKey,
}

impl ClavePrivadaReconstruida {
    pub fn firmar(&self, mensaje: &[u8]) -> ed25519_dalek::Signature {
        self.signing_key.sign(mensaje)
    }
}

pub fn reconstruir_clave_privada(
    passphrase: &PassphraseSecreta,
    blob: &EncryptedPrivateKeyBlob,
    email: &str,
) -> anyhow::Result<ClavePrivadaReconstruida> {
    let mut privadas = clave_privada::descifrar_clave_privada(passphrase, blob, email.as_bytes())
        .map_err(|_| anyhow::anyhow!("passphrase incorrecta o blob corrupto"))?;

    let mut x25519_bytes = [0u8; 32];
    let mut ed25519_bytes = [0u8; 32];
    x25519_bytes.copy_from_slice(&privadas[..32]);
    ed25519_bytes.copy_from_slice(&privadas[32..]);
    privadas.zeroize();

    let x25519 = StaticSecret::from(x25519_bytes);
    let signing_key = SigningKey::from_bytes(&ed25519_bytes);
    x25519_bytes.zeroize();
    ed25519_bytes.zeroize();

    Ok(ClavePrivadaReconstruida { x25519, signing_key })
}

pub fn sellar_dek_para(publica_x25519_bytes: &[u8; 32], dek: &ClaveSecreta32) -> Vec<u8> {
    sellado::sellar_dek(&x25519_dalek::PublicKey::from(*publica_x25519_bytes), dek)
}

pub fn abrir_dek(privada: &StaticSecret, sellado_bytes: &[u8]) -> anyhow::Result<ClaveSecreta32> {
    sellado::abrir_dek(privada, sellado_bytes).map_err(|_| anyhow::anyhow!("no se pudo abrir la DEK sellada"))
}

pub fn generar_dek() -> ClaveSecreta32 {
    SecretBox::new(Box::new(ellkan_crypto::aleatoriedad::bytes_aleatorios::<32>()))
}

/// AAD fijo por recurso — `resource_id || created_by`. Es el mismo para
/// cualquier destinatario que lea el recurso, no varía por quién descifra (a
/// diferencia de usar el `user_id` del lector, que rompería el descifrado
/// para todos menos el creador).
pub fn aad_de_recurso(resource_id: uuid::Uuid, created_by: uuid::Uuid) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32);
    aad.extend_from_slice(resource_id.as_bytes());
    aad.extend_from_slice(created_by.as_bytes());
    aad
}

pub fn cifrar_json(dek: &ClaveSecreta32, valor: &serde_json::Value, aad: &[u8]) -> anyhow::Result<Envoltura> {
    let bytes = serde_json::to_vec(valor)?;
    aead::cifrar(dek, &bytes, aad).map_err(|_| anyhow::anyhow!("fallo al cifrar"))
}

pub fn descifrar_json(dek: &ClaveSecreta32, envoltura: &Envoltura, aad: &[u8]) -> anyhow::Result<serde_json::Value> {
    let bytes = aead::descifrar(dek, envoltura, aad).map_err(|_| anyhow::anyhow!("fallo al descifrar"))?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Genera el token de dispositivo persistente (F-02) — sólo su hash viaja al
/// backend, nunca el token en claro.
pub fn generar_device_token() -> [u8; 32] {
    ellkan_crypto::aleatoriedad::bytes_aleatorios()
}

pub fn hash_device_token(token: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(token).to_vec()
}
