// Autor: Athan Espinoza

//! Separación de dominios: Argon2id nunca alimenta un AEAD directamente,
//! siempre pasa por HKDF con un `info` (contexto) distinto por propósito.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use secrecy::{ExposeSecret, SecretBox};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::secretos::{ClaveSecreta32, PassphraseSecreta};

/// QA-03: parámetros de Argon2id con los que se selló un blob. Viajan con
/// él (`user_keys.kdf_params`): quien lo abre usa los del blob, no una
/// constante, así se pueden subir por usuario sin romper a nadie.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ParametrosKdf {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl ParametrosKdf {
    /// Los de toda cuenta creada antes de QA-03: el mínimo de OWASP
    /// (19 MiB / 2 iteraciones / 1 hilo). Se siguen aceptando para abrir; la
    /// cuenta se re-sella con `ACTUAL` en su siguiente desbloqueo.
    pub const LEGADO: Self = Self { m_cost_kib: 19_456, t_cost: 2, p_cost: 1 };
    /// Los de toda clave que se sella desde QA-03: 64 MiB / 3 iteraciones.
    pub const ACTUAL: Self = Self { m_cost_kib: 65_536, t_cost: 3, p_cost: 1 };
    /// Tope que un cliente acepta derivar: un servidor hostil no puede
    /// pedirle 4 GiB para colgarlo.
    pub const MAXIMO: Self = Self { m_cost_kib: 1_048_576, t_cost: 10, p_cost: 4 };

    /// Entre `LEGADO` y `MAXIMO`: se puede abrir un blob con estos.
    pub fn aceptables_para_abrir(&self) -> bool {
        self.dentro_de(&Self::LEGADO, &Self::MAXIMO)
    }

    /// Entre `ACTUAL` y `MAXIMO`: el servidor no acepta guardar un blob
    /// nuevo sellado con menos.
    pub fn aceptables_para_sellar(&self) -> bool {
        self.dentro_de(&Self::ACTUAL, &Self::MAXIMO)
    }

    fn dentro_de(&self, min: &Self, max: &Self) -> bool {
        (min.m_cost_kib..=max.m_cost_kib).contains(&self.m_cost_kib)
            && (min.t_cost..=max.t_cost).contains(&self.t_cost)
            && (min.p_cost..=max.p_cost).contains(&self.p_cost)
    }

    /// Forma canónica de 12 bytes (tres u32 little-endian), para firmarlos.
    pub fn a_bytes(&self) -> [u8; 12] {
        let mut b = [0u8; 12];
        b[..4].copy_from_slice(&self.m_cost_kib.to_le_bytes());
        b[4..8].copy_from_slice(&self.t_cost.to_le_bytes());
        b[8..].copy_from_slice(&self.p_cost.to_le_bytes());
        b
    }
}

/// Tags de contexto HKDF — un `info` nuevo por propósito, nunca se reusa la
/// clave maestra tal cual.
pub mod contexto {
    pub const CIFRADO_CLAVE_PRIVADA: &[u8] = b"ellkan:v1:private-key-wrap";
    /// F-38: envoltura de la passphrase para el desbloqueo local con TOTP.
    pub const DESBLOQUEO_TOTP: &[u8] = b"ellkan:v1:totp-unlock-wrap";
    /// F-26: combinación de la clave del fragmento de la URL con la capa
    /// opcional de passphrase de un external share.
    pub const EXTERNAL_SHARE_PASSPHRASE: &[u8] = b"ellkan:v1:external-share-passphrase-combine";
    /// F-03 (PRF): envoltura de la passphrase con el output de la extensión
    /// PRF de WebAuthn — mismo criterio que `DESBLOQUEO_TOTP` (secreto de
    /// alta entropía ya generado por CSPRNG/hardware, no una passphrase
    /// humana, así que tampoco pasa por Argon2id acá).
    pub const DESBLOQUEO_PRF: &[u8] = b"ellkan:v1:prf-unlock-wrap";
    /// QA-03: `auth_key`, lo que el cliente le prueba al servidor para que
    /// le entregue el blob. Independiente de `CIFRADO_CLAVE_PRIVADA`: quien
    /// la conoce (el servidor) no puede abrir el blob con ella.
    pub const AUTENTICACION: &[u8] = b"ellkan:v1:auth";
    /// QA-03: dominio del verificador que guarda el servidor.
    pub const VERIFICADOR_AUTENTICACION: &[u8] = b"ellkan:v1:auth-verifier:";
}

#[derive(Debug, thiserror::Error)]
pub enum ErrorDerivacion {
    #[error("parámetros de Argon2id inválidos: {0}")]
    ParametrosInvalidos(#[from] argon2::Error),
    #[error("parámetros de Argon2id fuera del rango aceptado")]
    FueraDeRango,
}

/// QA-03: lo que sale de la passphrase al desbloquear. Las dos claves vienen
/// de la misma maestra por HKDF con `info` distinto: `auth_key` se le muestra
/// al servidor; `clave_envoltura` abre el blob y nunca sale del cliente.
pub struct Desbloqueo {
    pub auth_key: ClaveSecreta32,
    pub clave_envoltura: ClaveSecreta32,
}

/// QA-03: un solo Argon2id para las dos claves del desbloqueo.
pub fn derivar_desbloqueo(
    passphrase: &PassphraseSecreta,
    salt: &[u8; 16],
    parametros: &ParametrosKdf,
) -> Result<Desbloqueo, ErrorDerivacion> {
    let maestra = derivar_clave_maestra(passphrase, salt, parametros)?;
    Ok(Desbloqueo {
        auth_key: derivar_subclave(&maestra, contexto::AUTENTICACION),
        clave_envoltura: derivar_subclave(&maestra, contexto::CIFRADO_CLAVE_PRIVADA),
    })
}

/// QA-03: lo que guarda el servidor (`user_keys.auth_verifier`) en vez de
/// la `auth_key`. Basta SHA-256 con dominio: `auth_key` ya tiene 256 bits y
/// sale de Argon2id, así que quien robe el verificador no ataca nada que no
/// pudiera atacar con el blob.
pub fn verificador_auth(auth_key: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(contexto::VERIFICADOR_AUTENTICACION);
    h.update(auth_key);
    h.finalize().into()
}

/// QA-03: compara en tiempo constante la `auth_key` recibida con el
/// verificador guardado.
pub fn auth_key_coincide(auth_key: &[u8], verificador: &[u8]) -> bool {
    crate::comparacion::secreto_coincide(verificador, &verificador_auth(auth_key))
}

/// Deriva la clave maestra desde la passphrase (el paso caro). Nunca se usa
/// para cifrar directamente — siempre pasa por `derivar_subclave`.
pub fn derivar_clave_maestra(
    passphrase: &PassphraseSecreta,
    salt: &[u8; 16],
    parametros: &ParametrosKdf,
) -> Result<ClaveSecreta32, ErrorDerivacion> {
    if !parametros.aceptables_para_abrir() {
        return Err(ErrorDerivacion::FueraDeRango);
    }
    let params =
        Params::new(parametros.m_cost_kib, parametros.t_cost, parametros.p_cost, Some(32)).map_err(ErrorDerivacion::ParametrosInvalidos)?;
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
    hk.expand(info, &mut subclave).expect("32 bytes está dentro del límite de HKDF-SHA256");
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
    hk.expand(info, &mut subclave).expect("32 bytes está dentro del límite de HKDF-SHA256");
    let resultado = SecretBox::new(Box::new(subclave));
    subclave.zeroize();
    resultado
}

/// Combina dos secretos independientes en una única clave (F-26: la clave
/// del fragmento de la URL, que nunca llega al servidor, con el output de
/// Argon2id de la capa opcional de passphrase) — HKDF-Extract con `a` como
/// salt y `b` como material de entrada, luego expand con `info`. Comprometer
/// uno solo de los dos secretos no alcanza para reconstruir la clave final.
pub fn combinar_secretos(a: &[u8], b: &[u8], info: &[u8]) -> ClaveSecreta32 {
    let hk = Hkdf::<Sha256>::new(Some(a), b);
    let mut combinada = [0u8; 32];
    hk.expand(info, &mut combinada).expect("32 bytes está dentro del límite de HKDF-SHA256");
    let resultado = SecretBox::new(Box::new(combinada));
    combinada.zeroize();
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
        let a = derivar_clave_maestra(&passphrase("correcto-caballo-batería-grapa"), &salt, &ParametrosKdf::LEGADO).unwrap();
        let b = derivar_clave_maestra(&passphrase("correcto-caballo-batería-grapa"), &salt, &ParametrosKdf::LEGADO).unwrap();
        assert_eq!(a.expose_secret(), b.expose_secret());
    }

    #[test]
    fn distinta_passphrase_deriva_distinta_clave() {
        let salt = [7u8; 16];
        let a = derivar_clave_maestra(&passphrase("passphrase-uno"), &salt, &ParametrosKdf::LEGADO).unwrap();
        let b = derivar_clave_maestra(&passphrase("passphrase-dos"), &salt, &ParametrosKdf::LEGADO).unwrap();
        assert_ne!(a.expose_secret(), b.expose_secret());
    }

    #[test]
    fn distinto_info_deriva_subclaves_independientes() {
        let maestra = derivar_clave_maestra(&passphrase("passphrase"), &[1u8; 16], &ParametrosKdf::LEGADO).unwrap();
        let sub_a = derivar_subclave(&maestra, b"contexto-a");
        let sub_b = derivar_subclave(&maestra, b"contexto-b");
        assert_ne!(sub_a.expose_secret(), sub_b.expose_secret());
    }

    #[test]
    fn subclave_nunca_es_igual_a_la_clave_maestra() {
        let maestra = derivar_clave_maestra(&passphrase("passphrase"), &[1u8; 16], &ParametrosKdf::LEGADO).unwrap();
        let sub = derivar_subclave(&maestra, contexto::CIFRADO_CLAVE_PRIVADA);
        assert_ne!(maestra.expose_secret(), sub.expose_secret());
    }

    #[test]
    fn rango_de_parametros() {
        assert!(ParametrosKdf::LEGADO.aceptables_para_abrir());
        assert!(!ParametrosKdf::LEGADO.aceptables_para_sellar());
        assert!(ParametrosKdf::ACTUAL.aceptables_para_sellar());
        let enorme = ParametrosKdf { m_cost_kib: 4 * 1_048_576, ..ParametrosKdf::ACTUAL };
        assert!(!enorme.aceptables_para_abrir());
        let flojo = ParametrosKdf { m_cost_kib: 1024, t_cost: 1, p_cost: 1 };
        assert!(matches!(
            derivar_clave_maestra(&passphrase("x"), &[1u8; 16], &flojo),
            Err(ErrorDerivacion::FueraDeRango)
        ));
    }

    #[test]
    fn auth_key_y_clave_de_envoltura_son_independientes_y_verificables() {
        let d = derivar_desbloqueo(&passphrase("passphrase"), &[1u8; 16], &ParametrosKdf::LEGADO).unwrap();
        assert_ne!(d.auth_key.expose_secret(), d.clave_envoltura.expose_secret());
        let verificador = verificador_auth(d.auth_key.expose_secret());
        assert!(auth_key_coincide(d.auth_key.expose_secret(), &verificador));
        assert!(!auth_key_coincide(d.clave_envoltura.expose_secret(), &verificador));
        assert_ne!(verificador, *d.auth_key.expose_secret(), "el servidor no guarda la auth_key tal cual");
    }
}
