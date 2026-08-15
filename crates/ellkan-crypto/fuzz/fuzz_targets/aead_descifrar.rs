// Autor: Athan Espinoza

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use secrecy::SecretBox;

use ellkan_crypto::aead::{descifrar, Envoltura};
use ellkan_crypto::secretos::ClaveSecreta32;

/// Entrada arbitraria que imita una `Envoltura` recibida por red/DB — nonce,
/// ciphertext y AAD nunca deben hacer panic en `descifrar`, sólo devolver `Err`.
#[derive(Debug, Arbitrary)]
struct Entrada {
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
    aad: Vec<u8>,
}

fuzz_target!(|entrada: Entrada| {
    let clave: ClaveSecreta32 = SecretBox::new(Box::new([7u8; 32]));
    let envoltura = Envoltura { nonce: entrada.nonce, ciphertext: entrada.ciphertext };
    let _ = descifrar(&clave, &envoltura, &entrada.aad);
});
