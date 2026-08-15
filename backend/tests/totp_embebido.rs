// Autor: Athan Espinoza

//! F-08: `GET /resources/{id}/totp` refleja si el tipo de recurso declara
//! `totp_secret`, nunca expone contenido cifrado ni un código generado, y
//! exige permiso `read`.

mod common;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ellkan_crypto::aead;
use ellkan_crypto::sellado;
use secrecy::SecretBox;
use serde_json::{json, Value};
use uuid::Uuid;

async fn crear_recurso(entorno: &common::Entorno, sesion: Uuid, owner: &common::Usuario, slug: &str) -> Uuid {
    let dek_bytes: [u8; 32] = ellkan_crypto::aleatoriedad::bytes_aleatorios();
    let dek_secreta = SecretBox::new(Box::new(dek_bytes));
    let resource_id = Uuid::now_v7();
    let mut aad = Vec::new();
    aad.extend_from_slice(resource_id.as_bytes());
    aad.extend_from_slice(owner.user_id.as_bytes());
    let metadata_env = aead::cifrar(&dek_secreta, b"{}", &aad).unwrap();
    let secreto_env = aead::cifrar(&dek_secreta, b"{}", &aad).unwrap();
    let sealed_dek = sellado::sellar_dek(owner.x25519.publica(), &dek_secreta);

    let resp = entorno
        .cliente
        .post(format!("{}/resources", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({
            "id": resource_id,
            "resource_type_slug": slug,
            "metadata_ciphertext_b64": B64.encode(&metadata_env.ciphertext),
            "metadata_nonce_b64": B64.encode(metadata_env.nonce),
            "sealed_dek_b64": B64.encode(&sealed_dek),
            "secret_ciphertext_b64": B64.encode(&secreto_env.ciphertext),
            "secret_nonce_b64": B64.encode(secreto_env.nonce),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "crear recurso {slug} debería devolver 200");
    resource_id
}

#[tokio::test]
async fn recurso_login_password_totp_reporta_tiene_totp_true() {
    let entorno = common::levantar().await;
    let alice = common::registrar(&entorno, "alice-totp@test.ellkan").await;
    let sesion = common::login(&entorno, &alice).await;

    let resource_id = crear_recurso(&entorno, sesion, &alice, "login-password-totp").await;

    let resp = entorno
        .cliente
        .get(format!("{}/resources/{resource_id}/totp", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["tiene_totp"], true);
}

#[tokio::test]
async fn recurso_login_password_simple_reporta_tiene_totp_false() {
    let entorno = common::levantar().await;
    let alice = common::registrar(&entorno, "alice-totp-2@test.ellkan").await;
    let sesion = common::login(&entorno, &alice).await;

    let resource_id = crear_recurso(&entorno, sesion, &alice, "login-password").await;

    let resp = entorno
        .cliente
        .get(format!("{}/resources/{resource_id}/totp", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["tiene_totp"], false);
}

#[tokio::test]
async fn sin_permiso_read_devuelve_403() {
    let entorno = common::levantar().await;
    let alice = common::registrar(&entorno, "alice-totp-3@test.ellkan").await;
    let bob = common::registrar(&entorno, "bob-totp-3@test.ellkan").await;
    let sesion_alice = common::login(&entorno, &alice).await;
    let sesion_bob = common::login(&entorno, &bob).await;

    let resource_id = crear_recurso(&entorno, sesion_alice, &alice, "login-password-totp").await;

    let resp = entorno
        .cliente
        .get(format!("{}/resources/{resource_id}/totp", entorno.base))
        .bearer_auth(sesion_bob)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}
