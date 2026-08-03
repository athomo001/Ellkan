// Autor: Athan Espinoza

//! Generación de keypairs: X25519 para acuerdo de claves, Ed25519 para
//! firma/autenticación. Se mantienen deliberadamente separados — mezclar
//! dominios de firma y acuerdo de claves con una conversión biracional
//! Ed25519↔X25519 fue evaluado y rechazado: es un patrón de riesgo real, no
//! una optimización gratis.

use ed25519_dalek::SigningKey;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::ZeroizeOnDrop;

use crate::aleatoriedad::csprng;

/// Keypair X25519 para acuerdo de claves (sellado/apertura de DEKs, F-05).
#[derive(ZeroizeOnDrop)]
pub struct KeypairAcuerdo {
    #[zeroize(skip)]
    publica: X25519PublicKey,
    privada: StaticSecret,
}

impl KeypairAcuerdo {
    pub fn generar() -> Self {
        let mut rng = csprng();
        let privada = StaticSecret::random_from_rng(&mut rng);
        let publica = X25519PublicKey::from(&privada);
        Self { publica, privada }
    }

    pub fn publica(&self) -> &X25519PublicKey {
        &self.publica
    }

    pub fn privada(&self) -> &StaticSecret {
        &self.privada
    }
}

/// Keypair Ed25519 para firma (autenticación por firma de nonce, F-01/F-02).
pub struct KeypairFirma {
    firma: SigningKey,
}

impl KeypairFirma {
    pub fn generar() -> Self {
        let mut rng = csprng();
        Self {
            firma: SigningKey::generate(&mut rng),
        }
    }

    pub fn firmante(&self) -> &SigningKey {
        &self.firma
    }

    pub fn verificadora(&self) -> ed25519_dalek::VerifyingKey {
        self.firma.verifying_key()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, Verifier};

    #[test]
    fn dos_keypairs_de_acuerdo_son_distintos() {
        let a = KeypairAcuerdo::generar();
        let b = KeypairAcuerdo::generar();
        assert_ne!(a.publica().as_bytes(), b.publica().as_bytes());
    }

    #[test]
    fn diffie_hellman_produce_el_mismo_secreto_compartido() {
        let alice = KeypairAcuerdo::generar();
        let bob = KeypairAcuerdo::generar();
        let secreto_alice = alice.privada().diffie_hellman(bob.publica());
        let secreto_bob = bob.privada().diffie_hellman(alice.publica());
        assert_eq!(secreto_alice.as_bytes(), secreto_bob.as_bytes());
    }

    #[test]
    fn firma_ed25519_verifica_correctamente() {
        let par = KeypairFirma::generar();
        let mensaje = b"nonce-de-desafio-de-autenticacion";
        let firma = par.firmante().sign(mensaje);
        assert!(par.verificadora().verify(mensaje, &firma).is_ok());
    }

    #[test]
    fn firma_no_verifica_con_mensaje_distinto() {
        let par = KeypairFirma::generar();
        let firma = par.firmante().sign(b"mensaje-original");
        assert!(par.verificadora().verify(b"mensaje-alterado", &firma).is_err());
    }
}
