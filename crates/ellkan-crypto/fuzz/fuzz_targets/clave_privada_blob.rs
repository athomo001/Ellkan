// Autor: Athan Espinoza

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use secrecy::SecretBox;

use ellkan_crypto::aead::Envoltura;
use ellkan_crypto::clave_privada::{descifrar_clave_privada, EncryptedPrivateKeyBlob};
use ellkan_crypto::secretos::PassphraseSecreta;

/// Entrada arbitraria que imita `user_keys.encrypted_private_key_blob` tal
/// como llegaría de la base de datos — nunca debe hacer panic al descifrar.
#[derive(Debug, Arbitrary)]
struct Entrada {
    salt: [u8; 16],
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
    aad: Vec<u8>,
}

fuzz_target!(|entrada: Entrada| {
    let pass: PassphraseSecreta = SecretBox::new(Box::new("passphrase-de-fuzz".to_string()));
    let blob = EncryptedPrivateKeyBlob {
        salt: entrada.salt,
        envoltura: Envoltura { nonce: entrada.nonce, ciphertext: entrada.ciphertext },
    };
    let _ = descifrar_clave_privada(&pass, &blob, &entrada.aad);
});
