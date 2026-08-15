// Autor: Athan Espinoza

//! AEAD XChaCha20-Poly1305 para contenido de secreto y metadata.
//! El AAD (`resource_id`+`user_id`) es obligatorio en cada envoltura — sin
//! esto, un ciphertext válido podría reutilizarse fuera del contexto para el
//! que fue creado.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use secrecy::ExposeSecret;

use crate::aleatoriedad::bytes_aleatorios;
use crate::secretos::ClaveSecreta32;

/// Nonce (24 bytes) + ciphertext (incluye el tag de Poly1305 al final).
/// Nunca se reusa un nonce con la misma clave — se genera uno nuevo por cada
/// operación de cifrado.
#[derive(Debug, Clone)]
pub struct Envoltura {
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum ErrorAead {
    #[error("cifrado/descifrado AEAD falló (ciphertext inauténtico o parámetros inválidos)")]
    OperacionFallida,
}

/// Cifra `plaintext` con AAD obligatorio (típicamente `resource_id || user_id`)
/// — evita que un ciphertext válido se reutilice fuera del contexto para el
/// que fue creado.
pub fn cifrar(clave: &ClaveSecreta32, plaintext: &[u8], aad: &[u8]) -> Result<Envoltura, ErrorAead> {
    let cipher = XChaCha20Poly1305::new(&Key::from(*clave.expose_secret()));
    let nonce_bytes: [u8; 24] = bytes_aleatorios();
    let nonce = XNonce::from(nonce_bytes);
    let ciphertext = cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad })
        .map_err(|_| ErrorAead::OperacionFallida)?;
    Ok(Envoltura { nonce: nonce_bytes, ciphertext })
}

/// Descifra una `Envoltura` — el mismo `aad` usado al cifrar debe repetirse
/// exactamente, si no la verificación del tag falla.
pub fn descifrar(clave: &ClaveSecreta32, envoltura: &Envoltura, aad: &[u8]) -> Result<Vec<u8>, ErrorAead> {
    let cipher = XChaCha20Poly1305::new(&Key::from(*clave.expose_secret()));
    let nonce = XNonce::from(envoltura.nonce);
    cipher
        .decrypt(&nonce, Payload { msg: &envoltura.ciphertext, aad })
        .map_err(|_| ErrorAead::OperacionFallida)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretBox;

    fn clave_de_prueba() -> ClaveSecreta32 {
        SecretBox::new(Box::new(bytes_aleatorios::<32>()))
    }

    #[test]
    fn cifra_y_descifra_correctamente_con_mismo_aad() {
        let clave = clave_de_prueba();
        let aad = b"resource_id:1|user_id:2";
        let envoltura = cifrar(&clave, b"contenido secreto", aad).unwrap();
        let descifrado = descifrar(&clave, &envoltura, aad).unwrap();
        assert_eq!(descifrado, b"contenido secreto");
    }

    #[test]
    fn falla_si_el_aad_no_coincide() {
        let clave = clave_de_prueba();
        let envoltura = cifrar(&clave, b"contenido secreto", b"aad-original").unwrap();
        assert!(descifrar(&clave, &envoltura, b"aad-distinto").is_err());
    }

    #[test]
    fn falla_si_el_ciphertext_fue_alterado() {
        let clave = clave_de_prueba();
        let aad = b"aad";
        let mut envoltura = cifrar(&clave, b"contenido secreto", aad).unwrap();
        let ultimo = envoltura.ciphertext.len() - 1;
        envoltura.ciphertext[ultimo] ^= 0xFF;
        assert!(descifrar(&clave, &envoltura, aad).is_err());
    }

    #[test]
    fn falla_con_clave_distinta() {
        let clave_a = clave_de_prueba();
        let clave_b = clave_de_prueba();
        let aad = b"aad";
        let envoltura = cifrar(&clave_a, b"contenido secreto", aad).unwrap();
        assert!(descifrar(&clave_b, &envoltura, aad).is_err());
    }

    #[test]
    fn dos_cifrados_del_mismo_mensaje_usan_nonces_distintos() {
        let clave = clave_de_prueba();
        let a = cifrar(&clave, b"mismo mensaje", b"aad").unwrap();
        let b = cifrar(&clave, b"mismo mensaje", b"aad").unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }
}
