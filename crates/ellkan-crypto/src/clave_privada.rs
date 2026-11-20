// Autor: Athan Espinoza

//! Protección de la clave privada con passphrase: Argon2id → HKDF-SHA256
//! (dominio `contexto::CIFRADO_CLAVE_PRIVADA`) → XChaCha20-Poly1305. Nunca se
//! cachea la clave privada ya descifrada — se reconstruye en cada operación
//! desde `EncryptedPrivateKeyBlob` + la passphrase cacheada.

use zeroize::Zeroizing;

use crate::aead::{Envoltura, ErrorAead, cifrar, descifrar};
use crate::derivacion::{ErrorDerivacion, contexto, derivar_clave_maestra, derivar_subclave};
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
/// instante de uso. Hallazgo de seguridad (auditoría 2026-08-12, H-05/H-13):
/// antes devolvía `Vec<u8>` plano y delegaba el zeroize al llamador — un
/// llamador (`wasm_api.rs::abrir_clave_privada`) no lo hacía. Devolver
/// `Zeroizing<Vec<u8>>` hace el zeroize automático al salir de scope sin
/// depender de que cada llamador se acuerde.
pub fn descifrar_clave_privada(
    passphrase: &PassphraseSecreta,
    blob: &EncryptedPrivateKeyBlob,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ErrorClavePrivada> {
    let maestra = derivar_clave_maestra(passphrase, &blob.salt)?;
    let subclave = derivar_subclave(&maestra, contexto::CIFRADO_CLAVE_PRIVADA);
    Ok(Zeroizing::new(descifrar(&subclave, &blob.envoltura, aad)?))
}

/// QA-06: prefijo de dominio del mensaje que prueba la posesión de la
/// identidad al reemplazar el blob sellado. Distinto del challenge de login
/// (F-02, que firma el nonce crudo), así que ninguna de las dos firmas sirve
/// para la otra.
const DOMINIO_REEMPLAZO_CLAVE_PRIVADA: &[u8] = b"ellkan:v1:reemplazo-clave-privada:";

/// QA-06: mensaje que el cliente firma con su Ed25519 privada para que el
/// servidor acepte un blob nuevo. Ata el challenge de un solo uso
/// (`POST /auth/challenge`) a ese blob exacto (ciphertext, nonce y salt): una
/// firma capturada no sirve para subir otro contenido. Cada parte entra
/// hasheada, así todas miden 32 bytes y la concatenación no es ambigua.
pub fn mensaje_reemplazo_clave_privada(challenge: &[u8], blob: &[u8], nonce: &[u8], salt: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut mensaje = Vec::with_capacity(DOMINIO_REEMPLAZO_CLAVE_PRIVADA.len() + 4 * 32);
    mensaje.extend_from_slice(DOMINIO_REEMPLAZO_CLAVE_PRIVADA);
    for parte in [challenge, blob, nonce, salt] {
        mensaje.extend_from_slice(&Sha256::digest(parte));
    }
    mensaje
}

/// QA-06: firma del mensaje de `mensaje_reemplazo_clave_privada`.
pub fn firmar_reemplazo_clave_privada(ed25519_privada: &[u8; 32], challenge: &[u8], blob: &[u8], nonce: &[u8], salt: &[u8]) -> [u8; 64] {
    use ed25519_dalek::{Signer, SigningKey};
    SigningKey::from_bytes(ed25519_privada)
        .sign(&mensaje_reemplazo_clave_privada(challenge, blob, nonce, salt))
        .to_bytes()
}

/// QA-06: `true` sólo si `firma` es una firma Ed25519 estricta de la
/// identidad `publica_ed25519` sobre ese challenge y ese blob.
pub fn verificar_reemplazo_clave_privada(
    publica_ed25519: &[u8],
    firma: &[u8],
    challenge: &[u8],
    blob: &[u8],
    nonce: &[u8],
    salt: &[u8],
) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey};
    let (Ok(publica), Ok(firma)) = (<[u8; 32]>::try_from(publica_ed25519), <[u8; 64]>::try_from(firma)) else {
        return false;
    };
    let Ok(verificadora) = VerifyingKey::from_bytes(&publica) else {
        return false;
    };
    verificadora
        .verify_strict(&mensaje_reemplazo_clave_privada(challenge, blob, nonce, salt), &Signature::from_bytes(&firma))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretBox;

    #[test]
    fn la_firma_de_reemplazo_ata_challenge_y_blob() {
        use ed25519_dalek::{Signer, SigningKey};
        let privada = [7u8; 32];
        let publica = SigningKey::from_bytes(&privada).verifying_key().to_bytes();
        let (challenge, blob, nonce, salt) = ([1u8; 32], [2u8; 80], [3u8; 24], [4u8; 16]);
        let firma = firmar_reemplazo_clave_privada(&privada, &challenge, &blob, &nonce, &salt);

        assert!(verificar_reemplazo_clave_privada(&publica, &firma, &challenge, &blob, &nonce, &salt));
        assert!(!verificar_reemplazo_clave_privada(&publica, &firma, &[9u8; 32], &blob, &nonce, &salt));
        assert!(!verificar_reemplazo_clave_privada(&publica, &firma, &challenge, &[0u8; 80], &nonce, &salt));
        assert!(!verificar_reemplazo_clave_privada(&publica, &firma, &challenge, &blob, &[0u8; 24], &salt));
        assert!(!verificar_reemplazo_clave_privada(&publica, &firma, &challenge, &blob, &nonce, &[0u8; 16]));
        let otra = SigningKey::from_bytes(&[8u8; 32]).verifying_key().to_bytes();
        assert!(!verificar_reemplazo_clave_privada(&otra, &firma, &challenge, &blob, &nonce, &salt));

        // Separación de dominio: una firma de login (nonce crudo) no sirve acá.
        let firma_login = SigningKey::from_bytes(&privada).sign(&challenge).to_bytes();
        assert!(!verificar_reemplazo_clave_privada(&publica, &firma_login, &challenge, &blob, &nonce, &salt));
    }

    #[test]
    fn el_formato_del_mensaje_de_reemplazo_no_cambia() {
        let mensaje = mensaje_reemplazo_clave_privada(b"c", b"b", b"n", b"s");
        assert_eq!(mensaje.len(), DOMINIO_REEMPLAZO_CLAVE_PRIVADA.len() + 128);
        assert!(mensaje.starts_with(b"ellkan:v1:reemplazo-clave-privada:"));
    }

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
        assert_eq!(recuperada.as_slice(), &clave_privada);
    }

    #[test]
    fn passphrase_incorrecta_no_descifra() {
        let clave_privada = [42u8; 32];
        let aad = b"user_id:1";
        let blob = cifrar_clave_privada(&passphrase("passphrase-correcta"), [1u8; 16], &clave_privada, aad).unwrap();
        assert!(descifrar_clave_privada(&passphrase("passphrase-incorrecta"), &blob, aad).is_err());
    }
}
