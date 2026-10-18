// Autor: Athan Espinoza

//! Migración 0052: el código de verificación de dispositivo (F-02) se
//! invalida a los 5 intentos fallidos. Antes lo único que frenaba adivinarlo
//! era el límite por IP, que se relajó el 2026-10-17 para que muchas
//! personas detrás de una misma NAT puedan entrar a la vez.

mod common;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::Signer;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[tokio::test]
async fn cinco_codigos_incorrectos_invalidan_el_desafio_aunque_despues_llegue_el_correcto() {
    let entorno = common::levantar().await;
    let usuario = common::registrar(&entorno, "intentos@test.ellkan").await;

    let cuerpo: Value = entorno
        .cliente
        .post(format!("{}/auth/challenge", entorno.base))
        .json(&json!({ "email": usuario.email }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let nonce = B64.decode(cuerpo["nonce_b64"].as_str().unwrap()).unwrap();
    let firma = usuario.ed25519.firmante().sign(&nonce);
    let cuerpo: Value = entorno
        .cliente
        .post(format!("{}/auth/verify", entorno.base))
        .json(&json!({
            "email": usuario.email,
            "nonce_b64": B64.encode(&nonce),
            "signature_b64": B64.encode(firma.to_bytes()),
            "device_token_hash_b64": B64.encode(Sha256::digest(usuario.device_token)),
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(cuerpo["estado"], "pendiente_dispositivo");
    let desafio = cuerpo["device_challenge_id"].as_str().unwrap().to_string();
    let codigo = common::codigo_verificacion_dispositivo_encolado(&entorno.pool, &usuario.email).await;

    // Un código que seguro no es el correcto.
    let incorrecto = if codigo == "000000" { "111111" } else { "000000" };
    for _ in 0..5 {
        let resp = entorno
            .cliente
            .post(format!("{}/auth/verify-device", entorno.base))
            .json(&json!({ "device_challenge_id": desafio, "code": incorrecto }))
            .send()
            .await
            .unwrap();
        assert_ne!(resp.status(), 200);
    }

    let resp = entorno
        .cliente
        .post(format!("{}/auth/verify-device", entorno.base))
        .json(&json!({ "device_challenge_id": desafio, "code": codigo }))
        .send()
        .await
        .unwrap();
    assert_ne!(resp.status(), 200, "tras 5 fallos el desafío ya no acepta ni el código correcto");
}
