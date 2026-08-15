// Autor: Athan Espinoza

//! Desbloqueo de passphrase vía la extensión PRF de WebAuthn Level 3 (F-03):
//! una passkey con soporte PRF puede reemplazar por completo el paso de
//! escribir la passphrase al iniciar sesión — el output de la extensión
//! (32 bytes, alta entropía, sale del autenticador) envuelve la passphrase,
//! igual que el secreto TOTP local hace para F-38 (`totp.rs`). El servidor
//! nunca ve el output de PRF ni participa en este envoltorio — sólo guarda
//! y devuelve el blob opaco resultante (`passkeys.prf_wrapped_private_key`).

use secrecy::{ExposeSecret, SecretBox};

use crate::aead::{cifrar, descifrar, Envoltura, ErrorAead};
use crate::derivacion::{contexto, derivar_clave_desde_secreto};
use crate::secretos::PassphraseSecreta;

#[derive(Debug, thiserror::Error)]
pub enum ErrorDesenvolturaPrf {
    #[error(transparent)]
    Aead(#[from] ErrorAead),
    #[error("la passphrase descifrada no es UTF-8 válido")]
    Utf8Invalido,
}

/// Envuelve la passphrase con una clave derivada (HKDF, sin Argon2id) del
/// output de PRF de esta passkey.
pub fn envolver_passphrase(
    prf_output: &[u8],
    passphrase: &PassphraseSecreta,
    aad: &[u8],
) -> Result<Envoltura, ErrorAead> {
    let clave = derivar_clave_desde_secreto(prf_output, contexto::DESBLOQUEO_PRF);
    cifrar(&clave, passphrase.expose_secret().as_bytes(), aad)
}

/// Abre el envoltorio y reconstruye la passphrase a partir del output de PRF
/// obtenido en la ceremonia de login (`navigator.credentials.get` con la
/// extensión `prf` solicitada).
pub fn desenvolver_passphrase(
    prf_output: &[u8],
    envoltura: &Envoltura,
    aad: &[u8],
) -> Result<PassphraseSecreta, ErrorDesenvolturaPrf> {
    let clave = derivar_clave_desde_secreto(prf_output, contexto::DESBLOQUEO_PRF);
    let bytes = descifrar(&clave, envoltura, aad)?;
    let texto = String::from_utf8(bytes).map_err(|_| ErrorDesenvolturaPrf::Utf8Invalido)?;
    Ok(SecretBox::new(Box::new(texto)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prf_output_de_prueba(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn envuelve_y_desenvuelve_la_passphrase_correctamente() {
        let prf = prf_output_de_prueba(1);
        let pass: PassphraseSecreta = SecretBox::new(Box::new("passphrase-de-prueba".to_string()));
        let aad = b"credential_id:1";
        let envoltura = envolver_passphrase(&prf, &pass, aad).unwrap();
        let recuperada = desenvolver_passphrase(&prf, &envoltura, aad).unwrap();
        assert_eq!(recuperada.expose_secret(), "passphrase-de-prueba");
    }

    #[test]
    fn prf_output_distinto_no_desenvuelve() {
        let prf_a = prf_output_de_prueba(1);
        let prf_b = prf_output_de_prueba(2);
        let pass: PassphraseSecreta = SecretBox::new(Box::new("passphrase".to_string()));
        let envoltura = envolver_passphrase(&prf_a, &pass, b"aad").unwrap();
        assert!(desenvolver_passphrase(&prf_b, &envoltura, b"aad").is_err());
    }

    #[test]
    fn aad_distinto_no_desenvuelve() {
        let prf = prf_output_de_prueba(1);
        let pass: PassphraseSecreta = SecretBox::new(Box::new("passphrase".to_string()));
        let envoltura = envolver_passphrase(&prf, &pass, b"aad-original").unwrap();
        assert!(desenvolver_passphrase(&prf, &envoltura, b"aad-distinto").is_err());
    }
}
