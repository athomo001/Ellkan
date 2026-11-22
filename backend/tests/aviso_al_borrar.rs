// Autor: Athan Espinoza

//! Pendiente #50: borrar un recurso compartido avisa en vivo
//! (`GET /sync/eventos`) a los demás destinatarios, no sólo a quien lo borra.

mod common;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ellkan_crypto::{aead, sellado};
use secrecy::SecretBox;
use serde_json::json;
use uuid::Uuid;

#[tokio::test]
async fn el_destinatario_se_entera_en_vivo_del_borrado() {
    let entorno = common::levantar().await;
    let alice = common::registrar(&entorno, "alice@test.ellkan").await;
    let bob = common::registrar(&entorno, "bob@test.ellkan").await;
    let sesion_alice = common::login(&entorno, &alice).await;
    let sesion_bob = common::login(&entorno, &bob).await;

    let dek = SecretBox::new(Box::new(ellkan_crypto::aleatoriedad::bytes_aleatorios::<32>()));
    let id = Uuid::now_v7();
    let mut aad = id.as_bytes().to_vec();
    aad.extend_from_slice(alice.user_id.as_bytes());
    let metadata = aead::cifrar(&dek, br#"{"name":"x"}"#, &aad).unwrap();
    let secreto = aead::cifrar(&dek, br#"{"password":"x"}"#, &aad).unwrap();
    let resp = entorno
        .cliente
        .post(format!("{}/resources", entorno.base))
        .bearer_auth(sesion_alice)
        .json(&json!({
            "id": id,
            "resource_type_slug": "login-password",
            "metadata_ciphertext_b64": B64.encode(&metadata.ciphertext),
            "metadata_nonce_b64": B64.encode(metadata.nonce),
            "sealed_dek_b64": B64.encode(sellado::sellar_dek(alice.x25519.publica(), &dek)),
            "secret_ciphertext_b64": B64.encode(&secreto.ciphertext),
            "secret_nonce_b64": B64.encode(secreto.nonce),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = entorno
        .cliente
        .post(format!("{}/resources/{id}/share", entorno.base))
        .bearer_auth(sesion_alice)
        .json(&json!({
            "recipient_user_id": bob.user_id,
            "sealed_dek_b64": B64.encode(sellado::sellar_dek(bob.x25519.publica(), &dek)),
            "secret_ciphertext_b64": B64.encode(&secreto.ciphertext),
            "secret_nonce_b64": B64.encode(secreto.nonce),
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.status());

    // Bob escucha desde antes del borrado.
    let mut stream = entorno
        .cliente
        .get(format!("{}/sync/eventos", entorno.base))
        .bearer_auth(sesion_bob)
        .send()
        .await
        .unwrap();
    assert_eq!(stream.status(), 200);

    let resp = entorno
        .cliente
        .delete(format!("{}/resources/{id}", entorno.base))
        .bearer_auth(sesion_alice)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.status());

    let mut texto = String::new();
    let llego = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while let Some(trozo) = stream.chunk().await.unwrap() {
            texto.push_str(&String::from_utf8_lossy(&trozo));
            if texto.contains("event: cambio") {
                return;
            }
        }
    })
    .await;
    assert!(llego.is_ok(), "bob tiene que recibir el aviso del borrado; llegó: {texto}");
}
