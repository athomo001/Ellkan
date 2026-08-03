// Autor: Athan Espinoza

//! Sellado de DEK por destinatario (F-05) — equivalente a `crypto_box_seal`
//! de libsodium: caja anónima de un solo uso (keypair X25519 efímero interno,
//! el destinatario no necesita saber quién selló), vía el crate `crypto_box`
//! de la familia RustCrypto.

use crypto_box::{PublicKey as CajaPublica, SecretKey as CajaPrivada};
use secrecy::ExposeSecret;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::aleatoriedad::csprng_v6;
use crate::secretos::ClaveSecreta32;

#[derive(Debug, thiserror::Error)]
pub enum ErrorSellado {
    #[error("apertura de la caja sellada falló (ciphertext inauténtico o clave incorrecta)")]
    AperturaFallida,
}

fn a_caja_publica(publica: &X25519PublicKey) -> CajaPublica {
    CajaPublica::from_bytes(*publica.as_bytes())
}

fn a_caja_privada(privada: &StaticSecret) -> CajaPrivada {
    CajaPrivada::from_bytes(privada.to_bytes())
}

/// Sella una DEK para la clave pública de un destinatario — sólo ese
/// destinatario (con su clave privada X25519) puede abrirla.
pub fn sellar_dek(publica_destinatario: &X25519PublicKey, dek: &ClaveSecreta32) -> Vec<u8> {
    let caja = a_caja_publica(publica_destinatario);
    let mut rng = csprng_v6();
    caja.seal(&mut rng, dek.expose_secret())
        .expect("sellar una DEK de 32 bytes no debería fallar")
}

/// Abre una DEK sellada con la clave privada del destinatario.
pub fn abrir_dek(privada_destinatario: &StaticSecret, sellado: &[u8]) -> Result<ClaveSecreta32, ErrorSellado> {
    let caja = a_caja_privada(privada_destinatario);
    let bytes = caja.unseal(sellado).map_err(|_| ErrorSellado::AperturaFallida)?;
    let arreglo: [u8; 32] = bytes.try_into().map_err(|_| ErrorSellado::AperturaFallida)?;
    Ok(secrecy::SecretBox::new(Box::new(arreglo)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claves::KeypairAcuerdo;
    use crate::aleatoriedad::bytes_aleatorios;

    #[test]
    fn destinatario_correcto_abre_la_dek_sellada() {
        let destinatario = KeypairAcuerdo::generar();
        let dek: ClaveSecreta32 = secrecy::SecretBox::new(Box::new(bytes_aleatorios::<32>()));
        let sellado = sellar_dek(destinatario.publica(), &dek);
        let abierta = abrir_dek(destinatario.privada(), &sellado).unwrap();
        assert_eq!(abierta.expose_secret(), dek.expose_secret());
    }

    #[test]
    fn destinatario_incorrecto_no_puede_abrir() {
        let destinatario = KeypairAcuerdo::generar();
        let atacante = KeypairAcuerdo::generar();
        let dek: ClaveSecreta32 = secrecy::SecretBox::new(Box::new(bytes_aleatorios::<32>()));
        let sellado = sellar_dek(destinatario.publica(), &dek);
        assert!(abrir_dek(atacante.privada(), &sellado).is_err());
    }

    #[test]
    fn dos_sellados_de_la_misma_dek_son_distintos() {
        let destinatario = KeypairAcuerdo::generar();
        let dek: ClaveSecreta32 = secrecy::SecretBox::new(Box::new(bytes_aleatorios::<32>()));
        let a = sellar_dek(destinatario.publica(), &dek);
        let b = sellar_dek(destinatario.publica(), &dek);
        assert_ne!(a, b, "cada sellado usa un keypair efímero distinto");
    }
}
