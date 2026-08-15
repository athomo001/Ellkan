// Autor: Athan Espinoza

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;

use ellkan_crypto::claves::KeypairAcuerdo;
use ellkan_crypto::sellado::abrir_dek;

/// Un solo keypair fijo para todo el corrido — lo que se fuzzea es el sellado
/// recibido, no la generación de claves.
static DESTINATARIO: LazyLock<KeypairAcuerdo> = LazyLock::new(KeypairAcuerdo::generar);

fuzz_target!(|sellado: &[u8]| {
    let _ = abrir_dek(DESTINATARIO.privada(), sellado);
});
