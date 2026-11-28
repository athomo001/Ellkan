// Autor: Athan Espinoza

//! Protección de la clave privada con passphrase: Argon2id → HKDF-SHA256
//! (dominio `contexto::CIFRADO_CLAVE_PRIVADA`) → XChaCha20-Poly1305. Nunca se
//! cachea la clave privada ya descifrada — se reconstruye en cada operación
//! desde `EncryptedPrivateKeyBlob` + la passphrase cacheada.
//!
//! QA-03: del mismo Argon2id sale también la `auth_key` (otro `info` de
//! HKDF), que el servidor exige antes de entregar el blob. Sellar devuelve
//! las dos cosas: el blob para guardar y la `auth_key` para registrar el
//! verificador.

use zeroize::Zeroizing;

use crate::aead::{Envoltura, ErrorAead, cifrar, descifrar};
use crate::derivacion::{Desbloqueo, ErrorDerivacion, ParametrosKdf, derivar_desbloqueo};
use crate::secretos::{ClaveSecreta32, PassphraseSecreta};

#[derive(Debug, thiserror::Error)]
pub enum ErrorClavePrivada {
    #[error(transparent)]
    Derivacion(#[from] ErrorDerivacion),
    #[error(transparent)]
    Aead(#[from] ErrorAead),
}

/// Blob almacenado en `user_keys.encrypted_private_key_blob`, con la sal y
/// los parámetros de Argon2id con que se selló (`kdf_salt`, `kdf_params`).
#[derive(Debug, Clone)]
pub struct EncryptedPrivateKeyBlob {
    pub salt: [u8; 16],
    pub parametros: ParametrosKdf,
    pub envoltura: Envoltura,
}

/// QA-03: resultado de sellar: el blob y la `auth_key` del mismo Argon2id.
pub struct ClavePrivadaSellada {
    pub blob: EncryptedPrivateKeyBlob,
    pub auth_key: ClaveSecreta32,
}

/// Cifra una clave privada (32 bytes, X25519 `StaticSecret` o Ed25519
/// `SigningKey` en bytes) con una clave derivada de la passphrase — nunca con
/// el output de Argon2id directo.
pub fn cifrar_clave_privada(
    passphrase: &PassphraseSecreta,
    salt: [u8; 16],
    parametros: ParametrosKdf,
    clave_privada: &[u8],
    aad: &[u8],
) -> Result<ClavePrivadaSellada, ErrorClavePrivada> {
    let Desbloqueo { auth_key, clave_envoltura } = derivar_desbloqueo(passphrase, &salt, &parametros)?;
    let envoltura = cifrar(&clave_envoltura, clave_privada, aad)?;
    Ok(ClavePrivadaSellada { blob: EncryptedPrivateKeyBlob { salt, parametros, envoltura }, auth_key })
}

/// QA-03: abre la envoltura con la clave ya derivada (`Desbloqueo`), para
/// quien derivó una sola vez y ya usó la `auth_key` para pedir el blob.
pub fn descifrar_con_clave_de_envoltura(
    clave_envoltura: &ClaveSecreta32,
    envoltura: &Envoltura,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ErrorClavePrivada> {
    Ok(Zeroizing::new(descifrar(clave_envoltura, envoltura, aad)?))
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
    let desbloqueo = derivar_desbloqueo(passphrase, &blob.salt, &blob.parametros)?;
    descifrar_con_clave_de_envoltura(&desbloqueo.clave_envoltura, &blob.envoltura, aad)
}

/// #49: AAD del blob de clave privada desde el login por nombre de usuario:
/// el `user_id` con prefijo (nunca coincide con un correo, que era el AAD
/// anterior). El mismo formato que `frontend/src/lib/crypto/desbloqueo.ts::aadDeUsuario`.
pub fn aad_de_usuario(user_id: &str) -> Vec<u8> {
    format!("ellkan:user:{}", user_id.to_lowercase()).into_bytes()
}

/// #49: abre el blob probando primero el AAD nuevo (`user_id`) y después el
/// viejo (correo), derivando la passphrase una sola vez.
pub fn descifrar_clave_privada_con_aads(
    passphrase: &PassphraseSecreta,
    blob: &EncryptedPrivateKeyBlob,
    aads: &[&[u8]],
) -> Result<Zeroizing<Vec<u8>>, ErrorClavePrivada> {
    let desbloqueo = derivar_desbloqueo(passphrase, &blob.salt, &blob.parametros)?;
    let mut ultimo = None;
    for aad in aads {
        match descifrar_con_clave_de_envoltura(&desbloqueo.clave_envoltura, &blob.envoltura, aad) {
            Ok(abierta) => return Ok(abierta),
            Err(e) => ultimo = Some(e),
        }
    }
    Err(ultimo.expect("al menos un AAD"))
}

/// QA-06: prefijo de dominio del mensaje que prueba la posesión de la
/// identidad al reemplazar el blob sellado. Distinto del challenge de login
/// (F-02, que firma el nonce crudo), así que ninguna de las dos firmas sirve
/// para la otra. QA-03 lo subió a v2: ahora también firma los parámetros de
/// Argon2id y la `auth_key` nueva.
const DOMINIO_REEMPLAZO_CLAVE_PRIVADA: &[u8] = b"ellkan:v2:reemplazo-clave-privada:";

/// Lo que se reemplaza: el blob sellado completo y la `auth_key` nueva.
#[derive(Clone, Copy)]
pub struct Reemplazo<'a> {
    pub blob: &'a [u8],
    pub nonce: &'a [u8],
    pub salt: &'a [u8],
    pub parametros: &'a ParametrosKdf,
    pub auth_key: &'a [u8],
}

/// QA-06: mensaje que el cliente firma con su Ed25519 privada para que el
/// servidor acepte un blob nuevo. Ata el challenge de un solo uso
/// (`POST /auth/challenge`) a ese blob exacto (ciphertext, nonce, salt,
/// parámetros) y a su `auth_key` (QA-03): una firma capturada no sirve para
/// subir otro contenido ni para cambiar sólo el verificador. Cada parte entra
/// hasheada, así todas miden 32 bytes y la concatenación no es ambigua.
pub fn mensaje_reemplazo_clave_privada(challenge: &[u8], r: &Reemplazo<'_>) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let parametros = r.parametros.a_bytes();
    let mut mensaje = Vec::with_capacity(DOMINIO_REEMPLAZO_CLAVE_PRIVADA.len() + 6 * 32);
    mensaje.extend_from_slice(DOMINIO_REEMPLAZO_CLAVE_PRIVADA);
    for parte in [challenge, r.blob, r.nonce, r.salt, &parametros, r.auth_key] {
        mensaje.extend_from_slice(&Sha256::digest(parte));
    }
    mensaje
}

/// QA-06: firma del mensaje de `mensaje_reemplazo_clave_privada`.
pub fn firmar_reemplazo_clave_privada(ed25519_privada: &[u8; 32], challenge: &[u8], r: &Reemplazo<'_>) -> [u8; 64] {
    use ed25519_dalek::{Signer, SigningKey};
    SigningKey::from_bytes(ed25519_privada)
        .sign(&mensaje_reemplazo_clave_privada(challenge, r))
        .to_bytes()
}

/// QA-06: `true` sólo si `firma` es una firma Ed25519 estricta de la
/// identidad `publica_ed25519` sobre ese challenge y ese reemplazo.
pub fn verificar_reemplazo_clave_privada(publica_ed25519: &[u8], firma: &[u8], challenge: &[u8], r: &Reemplazo<'_>) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey};
    let (Ok(publica), Ok(firma)) = (<[u8; 32]>::try_from(publica_ed25519), <[u8; 64]>::try_from(firma)) else {
        return false;
    };
    let Ok(verificadora) = VerifyingKey::from_bytes(&publica) else {
        return false;
    };
    verificadora
        .verify_strict(&mensaje_reemplazo_clave_privada(challenge, r), &Signature::from_bytes(&firma))
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
        let challenge = [1u8; 32];
        let r = Reemplazo {
            blob: &[2u8; 80],
            nonce: &[3u8; 24],
            salt: &[4u8; 16],
            parametros: &ParametrosKdf::ACTUAL,
            auth_key: &[5u8; 32],
        };
        let firma = firmar_reemplazo_clave_privada(&privada, &challenge, &r);

        assert!(verificar_reemplazo_clave_privada(&publica, &firma, &challenge, &r));
        assert!(!verificar_reemplazo_clave_privada(&publica, &firma, &[9u8; 32], &r));
        assert!(!verificar_reemplazo_clave_privada(
            &publica,
            &firma,
            &challenge,
            &Reemplazo { blob: &[0u8; 80], ..r }
        ));
        assert!(!verificar_reemplazo_clave_privada(
            &publica,
            &firma,
            &challenge,
            &Reemplazo { nonce: &[0u8; 24], ..r }
        ));
        assert!(!verificar_reemplazo_clave_privada(
            &publica,
            &firma,
            &challenge,
            &Reemplazo { salt: &[0u8; 16], ..r }
        ));
        assert!(!verificar_reemplazo_clave_privada(
            &publica,
            &firma,
            &challenge,
            &Reemplazo { parametros: &ParametrosKdf::LEGADO, ..r }
        ));
        assert!(!verificar_reemplazo_clave_privada(
            &publica,
            &firma,
            &challenge,
            &Reemplazo { auth_key: &[0u8; 32], ..r }
        ));
        let otra = SigningKey::from_bytes(&[8u8; 32]).verifying_key().to_bytes();
        assert!(!verificar_reemplazo_clave_privada(&otra, &firma, &challenge, &r));

        // Separación de dominio: una firma de login (nonce crudo) no sirve acá.
        let firma_login = SigningKey::from_bytes(&privada).sign(&challenge).to_bytes();
        assert!(!verificar_reemplazo_clave_privada(&publica, &firma_login, &challenge, &r));
    }

    #[test]
    fn el_formato_del_mensaje_de_reemplazo_no_cambia() {
        let r = Reemplazo {
            blob: b"b",
            nonce: b"n",
            salt: b"s",
            parametros: &ParametrosKdf::ACTUAL,
            auth_key: b"a",
        };
        let mensaje = mensaje_reemplazo_clave_privada(b"c", &r);
        assert_eq!(mensaje.len(), DOMINIO_REEMPLAZO_CLAVE_PRIVADA.len() + 192);
        assert!(mensaje.starts_with(b"ellkan:v2:reemplazo-clave-privada:"));
    }

    fn passphrase(valor: &str) -> PassphraseSecreta {
        SecretBox::new(Box::new(valor.to_string()))
    }

    #[test]
    fn cifra_y_descifra_la_clave_privada_correctamente() {
        let pass = passphrase("passphrase-de-prueba-suficientemente-larga");
        let clave_privada = [42u8; 32];
        let aad = b"user_id:1";
        let sellada = cifrar_clave_privada(&pass, [1u8; 16], ParametrosKdf::LEGADO, &clave_privada, aad).unwrap();
        let recuperada = descifrar_clave_privada(&pass, &sellada.blob, aad).unwrap();
        assert_eq!(recuperada.as_slice(), &clave_privada);
    }

    #[test]
    fn la_auth_key_de_sellar_es_la_del_desbloqueo() {
        use secrecy::ExposeSecret;
        let pass = passphrase("passphrase");
        let sellada = cifrar_clave_privada(&pass, [1u8; 16], ParametrosKdf::LEGADO, &[42u8; 64], b"aad").unwrap();
        let d = crate::derivacion::derivar_desbloqueo(&pass, &[1u8; 16], &ParametrosKdf::LEGADO).unwrap();
        assert_eq!(sellada.auth_key.expose_secret(), d.auth_key.expose_secret());
        let abierta = descifrar_con_clave_de_envoltura(&d.clave_envoltura, &sellada.blob.envoltura, b"aad").unwrap();
        assert_eq!(abierta.as_slice(), &[42u8; 64]);
    }

    #[test]
    fn passphrase_incorrecta_no_descifra() {
        let clave_privada = [42u8; 32];
        let aad = b"user_id:1";
        let sellada =
            cifrar_clave_privada(&passphrase("passphrase-correcta"), [1u8; 16], ParametrosKdf::LEGADO, &clave_privada, aad).unwrap();
        assert!(descifrar_clave_privada(&passphrase("passphrase-incorrecta"), &sellada.blob, aad).is_err());
    }
}
