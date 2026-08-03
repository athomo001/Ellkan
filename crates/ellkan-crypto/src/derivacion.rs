// Autor: Athan Espinoza

//! Separación de dominios: Argon2id nunca alimenta un AEAD directamente,
//! siempre pasa por HKDF con un `info` (contexto) distinto por propósito.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use secrecy::{ExposeSecret, SecretBox};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::secretos::{ClaveSecreta32, PassphraseSecreta};

/// Argon2id — mínimo recomendado por OWASP (Password Storage Cheat Sheet
/// vigente): 19 MiB / 2 iteraciones / 1 hilo. `kdf_params` en `user_keys`
/// permite subir esto por usuario en el futuro sin romper compatibilidad.
pub const ARGON2_M_COST_KIB: u32 = 19_456;
pub const ARGON2_T_COST: u32 = 2;
pub const ARGON2_P_COST: u32 = 1;

/// Tags de contexto HKDF — un `info` nuevo por propósito, nunca se reusa la
/// clave maestra tal cual.
pub mod contexto {
    pub const CIFRADO_CLAVE_PRIVADA: &[u8] = b"ellkan:v1:private-key-wrap";
    /// F-38: envoltura de la passphrase para el desbloqueo local con TOTP.
    pub const DESBLOQUEO_TOTP: &[u8] = b"ellkan:v1:totp-unlock-wrap";
}

#[derive(Debug, thiserror::Error)]
pub enum ErrorDerivacion {
    #[error("parámetros de Argon2id inválidos: {0}")]
    ParametrosInvalidos(#[from] argon2::Error),
}

/// Deriva la clave maestra desde la passphrase (el paso caro). Nunca se usa
/// para cifrar directamente — siempre pasa por `derivar_subclave`.
pub fn derivar_clave_maestra(
    passphrase: &PassphraseSecreta,
    salt: &[u8; 16],
) -> Result<ClaveSecreta32, ErrorDerivacion> {
    let params = Params::new(ARGON2_M_COST_KIB, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(ErrorDerivacion::ParametrosInvalidos)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut salida = [0u8; 32];
    argon2
        .hash_password_into(passphrase.expose_secret().as_bytes(), salt, &mut salida)
        .map_err(ErrorDerivacion::ParametrosInvalidos)?;
    let resultado = SecretBox::new(Box::new(salida));
    salida.zeroize();
    Ok(resultado)
}

/// Deriva una subclave con dominio separado — HKDF-SHA256, `info` fija el
/// propósito. Dos llamadas con distinto `info` producen subclaves
/// independientes: romper una no compromete la otra.
pub fn derivar_subclave(clave_maestra: &ClaveSecreta32, info: &[u8]) -> ClaveSecreta32 {
    let hk = Hkdf::<Sha256>::new(None, clave_maestra.expose_secret());
    let mut subclave = [0u8; 32];
    hk.expand(info, &mut subclave)
        .expect("32 bytes está dentro del límite de HKDF-SHA256");
    let resultado = SecretBox::new(Box::new(subclave));
    subclave.zeroize();
    resultado
}

/// Deriva una clave directamente vía HKDF desde un secreto que ya tiene
/// suficiente entropía por sí solo (ej. el secreto TOTP de F-38) — a
/// diferencia de `derivar_clave_maestra`, deliberadamente **no** pasa por
/// Argon2id: ese costo existe para estirar una passphrase humana de baja
/// entropía, no para un secreto de 160 bits generado por CSPRNG.
pub fn derivar_clave_desde_secreto(secreto: &[u8], info: &[u8]) -> ClaveSecreta32 {
    let hk = Hkdf::<Sha256>::new(None, secreto);
    let mut subclave = [0u8; 32];
    hk.expand(info, &mut subclave)
        .expect("32 bytes está dentro del límite de HKDF-SHA256");
    let resultado = SecretBox::new(Box::new(subclave));
    subclave.zeroize();
    resultado
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passphrase(valor: &str) -> PassphraseSecreta {
        SecretBox::new(Box::new(valor.to_string()))
    }

    #[test]
    fn misma_passphrase_y_salt_derivan_la_misma_clave() {
        let salt = [7u8; 16];
        let a = derivar_clave_maestra(&passphrase("correcto-caballo-batería-grapa"), &salt).unwrap();
        let b = derivar_clave_maestra(&passphrase("correcto-caballo-batería-grapa"), &salt).unwrap();
        assert_eq!(a.expose_secret(), b.expose_secret());
    }

    #[test]
    fn distinta_passphrase_deriva_distinta_clave() {
        let salt = [7u8; 16];
        let a = derivar_clave_maestra(&passphrase("passphrase-uno"), &salt).unwrap();
        let b = derivar_clave_maestra(&passphrase("passphrase-dos"), &salt).unwrap();
        assert_ne!(a.expose_secret(), b.expose_secret());
    }

    #[test]
    fn distinto_info_deriva_subclaves_independientes() {
        let maestra = derivar_clave_maestra(&passphrase("passphrase"), &[1u8; 16]).unwrap();
        let sub_a = derivar_subclave(&maestra, b"contexto-a");
        let sub_b = derivar_subclave(&maestra, b"contexto-b");
        assert_ne!(sub_a.expose_secret(), sub_b.expose_secret());
    }

    #[test]
    fn subclave_nunca_es_igual_a_la_clave_maestra() {
        let maestra = derivar_clave_maestra(&passphrase("passphrase"), &[1u8; 16]).unwrap();
        let sub = derivar_subclave(&maestra, contexto::CIFRADO_CLAVE_PRIVADA);
        assert_ne!(maestra.expose_secret(), sub.expose_secret());
    }
}
