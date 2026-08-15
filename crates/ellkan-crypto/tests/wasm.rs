// Autor: Athan Espinoza

//! Validación real del crate corriendo en `wasm32-unknown-unknown` dentro de
//! Node (`wasm-pack test --node`) — no sólo `cargo build`/`cargo clippy` sobre
//! ese target, que no ejercitan la entropía `getrandom`/`wasm_js` en tiempo
//! de ejecución.
#![cfg(target_arch = "wasm32")]

use ed25519_dalek::{Signer, Verifier};
use secrecy::{ExposeSecret, SecretBox};
use wasm_bindgen_test::*;

use ellkan_crypto::aead::{cifrar, descifrar};
use ellkan_crypto::claves::{KeypairAcuerdo, KeypairFirma};
use ellkan_crypto::clave_privada::{cifrar_clave_privada, descifrar_clave_privada};
use ellkan_crypto::sellado::{abrir_dek, sellar_dek};

// Sin `wasm_bindgen_test_configure!`, este archivo corre en Node
// (`wasm-pack test --node`); la variante para navegador headless vive en
// `wasm_browser.rs` — la macro de configuración es por archivo, no admite
// "correr en los dos" a la vez en el mismo binario de test.

#[wasm_bindgen_test]
fn genera_keypairs_con_entropia_real_del_entorno_js() {
    let acuerdo_a = KeypairAcuerdo::generar();
    let acuerdo_b = KeypairAcuerdo::generar();
    assert_ne!(acuerdo_a.publica().as_bytes(), acuerdo_b.publica().as_bytes());

    let firma = KeypairFirma::generar();
    let mensaje = b"nonce-de-prueba";
    let rubrica = firma.firmante().sign(mensaje);
    assert!(firma.verificadora().verify(mensaje, &rubrica).is_ok());
}

#[wasm_bindgen_test]
fn aead_cifra_y_descifra_corriendo_en_node() {
    let clave = SecretBox::new(Box::new(ellkan_crypto::aleatoriedad::bytes_aleatorios::<32>()));
    let aad = b"aad-de-prueba";
    let envoltura = cifrar(&clave, b"contenido secreto", aad).unwrap();
    let descifrado = descifrar(&clave, &envoltura, aad).unwrap();
    assert_eq!(descifrado, b"contenido secreto");
}

#[wasm_bindgen_test]
fn clave_privada_argon2id_hkdf_aead_roundtrip_en_node() {
    let pass = SecretBox::new(Box::new("passphrase-de-prueba-wasm".to_string()));
    let clave_privada = [9u8; 32];
    let aad = b"user_id:wasm-test";
    let blob = cifrar_clave_privada(&pass, [3u8; 16], &clave_privada, aad).unwrap();
    let recuperada = descifrar_clave_privada(&pass, &blob, aad).unwrap();
    assert_eq!(recuperada.as_slice(), &clave_privada);
}

#[wasm_bindgen_test]
fn sellado_de_dek_abre_correctamente_en_node() {
    let destinatario = KeypairAcuerdo::generar();
    let dek = SecretBox::new(Box::new(ellkan_crypto::aleatoriedad::bytes_aleatorios::<32>()));
    let sellado = sellar_dek(destinatario.publica(), &dek);
    let abierta = abrir_dek(destinatario.privada(), &sellado).unwrap();
    assert_eq!(abierta.expose_secret(), dek.expose_secret());
}
