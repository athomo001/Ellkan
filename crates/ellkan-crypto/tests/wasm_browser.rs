// Autor: Athan Espinoza

//! Misma validación que `wasm.rs` pero forzada a correr en navegador headless
//! (`wasm-pack test --headless --chrome`) — la macro de configuración de
//! `wasm-bindgen-test` es por archivo, no admite Node y navegador a la vez
//! en el mismo binario.
#![cfg(target_arch = "wasm32")]

use ed25519_dalek::{Signer, Verifier};
use secrecy::{ExposeSecret, SecretBox};
use wasm_bindgen_test::*;

use ellkan_crypto::aead::{cifrar, descifrar};
use ellkan_crypto::claves::{KeypairAcuerdo, KeypairFirma};
use ellkan_crypto::clave_privada::{cifrar_clave_privada, descifrar_clave_privada};
use ellkan_crypto::sellado::{abrir_dek, sellar_dek};

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn genera_keypairs_con_entropia_real_del_navegador() {
    let acuerdo_a = KeypairAcuerdo::generar();
    let acuerdo_b = KeypairAcuerdo::generar();
    assert_ne!(acuerdo_a.publica().as_bytes(), acuerdo_b.publica().as_bytes());

    let firma = KeypairFirma::generar();
    let mensaje = b"nonce-de-prueba";
    let rubrica = firma.firmante().sign(mensaje);
    assert!(firma.verificadora().verify(mensaje, &rubrica).is_ok());
}

#[wasm_bindgen_test]
fn aead_cifra_y_descifra_corriendo_en_navegador() {
    let clave = SecretBox::new(Box::new(ellkan_crypto::aleatoriedad::bytes_aleatorios::<32>()));
    let aad = b"aad-de-prueba";
    let envoltura = cifrar(&clave, b"contenido secreto", aad).unwrap();
    let descifrado = descifrar(&clave, &envoltura, aad).unwrap();
    assert_eq!(descifrado, b"contenido secreto");
}

#[wasm_bindgen_test]
fn clave_privada_argon2id_hkdf_aead_roundtrip_en_navegador() {
    let pass = SecretBox::new(Box::new("passphrase-de-prueba-wasm".to_string()));
    let clave_privada = [9u8; 32];
    let aad = b"user_id:wasm-test";
    let blob = cifrar_clave_privada(&pass, [3u8; 16], &clave_privada, aad).unwrap();
    let recuperada = descifrar_clave_privada(&pass, &blob, aad).unwrap();
    assert_eq!(recuperada, clave_privada);
}

#[wasm_bindgen_test]
fn sellado_de_dek_abre_correctamente_en_navegador() {
    let destinatario = KeypairAcuerdo::generar();
    let dek = SecretBox::new(Box::new(ellkan_crypto::aleatoriedad::bytes_aleatorios::<32>()));
    let sellado = sellar_dek(destinatario.publica(), &dek);
    let abierta = abrir_dek(destinatario.privada(), &sellado).unwrap();
    assert_eq!(abierta.expose_secret(), dek.expose_secret());
}
