// Autor: Athan Espinoza

//! Protección de la clave privada con passphrase: Argon2id → HKDF-SHA256
//! (dominio `contexto::CIFRADO_CLAVE_PRIVADA`) → XChaCha20-Poly1305. Nunca se
//! cachea la clave privada ya descifrada — se reconstruye en cada operación
//! desde `EncryptedPrivateKeyBlob` + la passphrase cacheada.

use crate::aead::{cifrar, descifrar, Envoltura, ErrorAead};
use crate::derivacion::{contexto, derivar_clave_maestra, derivar_subclave, ErrorDerivacion};
use crate::secretos::PassphraseSecreta;

#[derive(Debug, thiserror::Error)]
pub enum ErrorClavePrivada {
    #[error(transparent)]
    Derivacion(#[from] ErrorDerivacion),
    #[error(transparent)]
    Aead(#[from] ErrorAead),
}

/// Blob almacenado en `user_keys.encrypted_private_key_blob`.
#[derive(Debug, Clone)]
pub struct EncryptedPrivateKeyBlob {
    pub salt: [u8; 16],
    pub envoltura: Envoltura,
}

/// Cifra una clave privada (32 bytes, X25519 `StaticSecret` o Ed25519
/// `SigningKey` en bytes) con una clave derivada de la passphrase — nunca con
/// el output de Argon2id directo.
pub fn cifrar_clave_privada(
    passphrase: &PassphraseSecreta,
    salt: [u8; 16],
    clave_privada: &[u8],
    aad: &[u8],
) -> Result<EncryptedPrivateKeyBlob, ErrorClavePrivada> {
    let maestra = derivar_clave_maestra(passphrase, &salt)?;
    let subclave = derivar_subclave(&maestra, contexto::CIFRADO_CLAVE_PRIVADA);
    let envoltura = cifrar(&subclave, clave_privada, aad)?;
    Ok(EncryptedPrivateKeyBlob { salt, envoltura })
}

/// Descifra el blob — reconstruye la clave privada en claro sólo para el
/// instante de uso; el llamador es responsable de envolverla en un tipo que
/// haga zeroize al salir de scope.
pub fn descifrar_clave_privada(
    passphrase: &PassphraseSecreta,
    blob: &EncryptedPrivateKeyBlob,
    aad: &[u8],
) -> Result<Vec<u8>, ErrorClavePrivada> {
    let maestra = derivar_clave_maestra(passphrase, &blob.salt)?;
    let subclave = derivar_subclave(&maestra, contexto::CIFRADO_CLAVE_PRIVADA);
    Ok(descifrar(&subclave, &blob.envoltura, aad)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretBox;

    fn passphrase(valor: &str) -> PassphraseSecreta {
        SecretBox::new(Box::new(valor.to_string()))
    }

    #[test]
    fn cifra_y_descifra_la_clave_privada_correctamente() {
        let pass = passphrase("passphrase-de-prueba-suficientemente-larga");
        let clave_privada = [42u8; 32];
        let aad = b"user_id:1";
        let blob = cifrar_clave_privada(&pass, [1u8; 16], &clave_privada, aad).unwrap();
        let recuperada = descifrar_clave_privada(&pass, &blob, aad).unwrap();
        assert_eq!(recuperada, clave_privada);
    }

    #[test]
    fn passphrase_incorrecta_no_descifra() {
        let clave_privada = [42u8; 32];
        let aad = b"user_id:1";
        let blob = cifrar_clave_privada(
            &passphrase("passphrase-correcta"),
            [1u8; 16],
            &clave_privada,
            aad,
        )
        .unwrap();
        assert!(descifrar_clave_privada(&passphrase("passphrase-incorrecta"), &blob, aad).is_err());
    }
}
