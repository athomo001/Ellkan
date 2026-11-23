// Autor: Athan Espinoza

//! QA-45: validación de entrada en el borde de la API, en un solo lugar.
//!
//! El servidor no puede descifrar nada, pero sí sabe qué forma tiene lo que
//! guarda: los tamaños criptográficos son fijos (un nonce de XChaCha20 que no
//! mide 24 bytes es basura que después ningún cliente puede abrir) y los
//! ciphertexts tienen un tope razonable (sin él, cada request podía guardar
//! hasta el límite del cuerpo, 3 MiB, por campo).

use crate::b64;
use crate::error::DomainError;

/// Nonce de XChaCha20-Poly1305.
pub const LARGO_NONCE: usize = 24;
/// Clave pública X25519 o Ed25519.
pub const LARGO_CLAVE_PUBLICA: usize = 32;
/// Sal de Argon2id.
pub const LARGO_SAL_KDF: usize = 16;
/// Clave de 32 bytes sellada con `crypto_box_seal` (32 de la clave efímera +
/// 16 de MAC + 32 de la clave): DEKs y claves privadas de metadata.
pub const LARGO_CLAVE_SELLADA: usize = 80;
/// Blob de la clave privada: 64 bytes (X25519 + Ed25519) + 16 de MAC.
pub const LARGO_BLOB_CLAVE_PRIVADA: usize = 80;

/// Tope de la metadata cifrada de un recurso (nombre, usuario, URIs, tags).
pub const MAX_METADATA: usize = 64 * 1024;
/// Tope del secreto cifrado de un recurso (contraseña, notas, TOTP, claves
/// SSH): holgado para notas largas y claves privadas, muy por debajo del
/// cuerpo máximo.
pub const MAX_SECRETO: usize = 1024 * 1024;
/// Tope del nombre cifrado de una carpeta.
pub const MAX_NOMBRE_CIFRADO: usize = 4 * 1024;

/// RFC 5321 §4.5.3.1: dirección completa y parte local.
const MAX_EMAIL: usize = 254;
const MAX_PARTE_LOCAL: usize = 64;
const MAX_NOMBRE_VISIBLE: usize = 200;

fn invalido(detalle: String) -> DomainError {
    DomainError::ValidacionInvalida(detalle)
}

/// QA-03: `auth_key` (HKDF de la clave maestra).
pub const LARGO_AUTH_KEY: usize = 32;

/// QA-03: todo blob nuevo llega con los parámetros de Argon2id con que se
/// selló (al menos los actuales: el servidor no acepta guardar uno más débil)
/// y la `auth_key` del mismo Argon2id. Devuelve la `auth_key` decodificada.
pub fn sello_nuevo(kdf_params: &ellkan_crypto::derivacion::ParametrosKdf, auth_key_b64: &str) -> Result<Vec<u8>, DomainError> {
    if !kdf_params.aceptables_para_sellar() {
        return Err(invalido("kdf_params por debajo del mínimo (64 MiB, t=3, p=1) o fuera de rango".into()));
    }
    b64_exacto(auth_key_b64, "auth_key_b64", LARGO_AUTH_KEY)
}

/// Base64 de exactamente `largo` bytes.
pub fn b64_exacto(valor: &str, campo: &str, largo: usize) -> Result<Vec<u8>, DomainError> {
    let bytes = b64::decode(valor).map_err(|_| invalido(format!("{campo} inválido")))?;
    if bytes.len() != largo {
        return Err(invalido(format!("{campo} debe medir {largo} bytes")));
    }
    Ok(bytes)
}

/// Base64 de entre 1 y `maximo` bytes.
pub fn b64_acotado(valor: &str, campo: &str, maximo: usize) -> Result<Vec<u8>, DomainError> {
    let bytes = b64::decode(valor).map_err(|_| invalido(format!("{campo} inválido")))?;
    if bytes.is_empty() || bytes.len() > maximo {
        return Err(invalido(format!("{campo} debe medir entre 1 y {maximo} bytes")));
    }
    Ok(bytes)
}

/// Formato de email: una sola `@`, partes no vacías, largos de RFC 5321, sin
/// espacios ni caracteres de control, y un dominio con forma de dominio. No
/// pretende validar todo lo que permite RFC 5322 (comillas, comentarios):
/// eso no lo usa nadie para una cuenta y es fuente de ataques.
pub fn email(valor: &str) -> Result<(), DomainError> {
    let error = || invalido("formato de email inválido".into());
    if valor.is_empty() || valor.len() > MAX_EMAIL || valor.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(error());
    }
    let (local, dominio) = valor.split_once('@').ok_or_else(error)?;
    if local.is_empty() || local.len() > MAX_PARTE_LOCAL || dominio.contains('@') {
        return Err(error());
    }
    let etiquetas_ok = dominio.split('.').all(|e| !e.is_empty() && !e.starts_with('-') && !e.ends_with('-'));
    if dominio.is_empty() || !etiquetas_ok {
        return Err(error());
    }
    Ok(())
}

/// Nombre visible: no vacío, hasta `MAX_NOMBRE_VISIBLE` caracteres, sin
/// caracteres de control (saltos de línea en un correo o un CSV).
pub fn nombre_visible(valor: &str) -> Result<(), DomainError> {
    let recortado = valor.trim();
    if recortado.is_empty() || recortado.chars().count() > MAX_NOMBRE_VISIBLE || recortado.chars().any(char::is_control) {
        return Err(invalido(format!(
            "el nombre debe tener entre 1 y {MAX_NOMBRE_VISIBLE} caracteres, sin saltos de línea"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(n: usize) -> String {
        b64::encode(&vec![7u8; n])
    }

    #[test]
    fn tamanos_exactos_y_topes() {
        assert!(b64_exacto(&b(24), "nonce", LARGO_NONCE).is_ok());
        assert!(b64_exacto(&b(23), "nonce", LARGO_NONCE).is_err());
        assert!(b64_exacto("no es base64!", "nonce", LARGO_NONCE).is_err());
        assert!(b64_acotado(&b(10), "x", 10).is_ok());
        assert!(b64_acotado(&b(11), "x", 10).is_err());
        assert!(b64_acotado("", "x", 10).is_err());
    }

    #[test]
    fn emails() {
        for ok in ["ana@x.com", "Ana.Perez+ellkan@sub.empresa.cl", "a@localhost"] {
            assert!(email(ok).is_ok(), "{ok}");
        }
        let largo = format!("{}@x.com", "a".repeat(65));
        for mal in [
            "",
            "ana",
            "@x.com",
            "ana@",
            "ana@@x.com",
            "a@b@c",
            "ana @x.com",
            "ana@x..com",
            "ana@-x.com",
            "ana@x.com\n",
            &largo,
        ] {
            assert!(email(mal).is_err(), "{mal:?}");
        }
    }

    #[test]
    fn nombres() {
        assert!(nombre_visible("Ana Pérez").is_ok());
        assert!(nombre_visible("   ").is_err());
        assert!(nombre_visible("Ana\nPérez").is_err());
        assert!(nombre_visible(&"a".repeat(201)).is_err());
    }
}
