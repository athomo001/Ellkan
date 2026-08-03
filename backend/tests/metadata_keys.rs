// Autor: Athan Espinoza

//! F-06 completo: sólo admin crea la metadata key compartida, máximo 2
//! activas simultáneas, y un recurso con metadata personal (`user_key`) no
//! puede compartirse.

mod common;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ellkan_crypto::aead;
use ellkan_crypto::claves::KeypairAcuerdo;
use ellkan_crypto::sellado;
use secrecy::SecretBox;
use serde_json::{json, Value};
use uuid::Uuid;

async fn crear_metadata_key(entorno: &common::Entorno, sesion_admin: Uuid) -> Value {
    let par = KeypairAcuerdo::generar();
    entorno
        .cliente
        .post(format!("{}/admin/metadata-keys", entorno.base))
        .bearer_auth(sesion_admin)
        .json(&json!({
            "id": Uuid::now_v7(),
            "public_key_x25519_b64": B64.encode(par.publica().as_bytes()),
            "fingerprint": "fp-de-prueba",
            "destinatarios": [],
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

#[tokio::test]
async fn usuario_no_admin_no_puede_crear_metadata_key() {
    let entorno = common::levantar().await;
    let user = common::registrar(&entorno, "no-admin-mk@test.ellkan").await;
    let sesion = common::login(&entorno, &user).await;

    let par = KeypairAcuerdo::generar();
    let resp = entorno
        .cliente
        .post(format!("{}/admin/metadata-keys", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({
            "id": Uuid::now_v7(),
            "public_key_x25519_b64": B64.encode(par.publica().as_bytes()),
            "fingerprint": "fp",
            "destinatarios": [],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn una_tercera_metadata_key_activa_falla_explicito() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin-mk@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion = common::login(&entorno, &admin).await;

    let primera = crear_metadata_key(&entorno, sesion).await;
    assert!(primera["expired_at"].is_null());

    let _segunda = crear_metadata_key(&entorno, sesion).await;

    let par = KeypairAcuerdo::generar();
    let resp = entorno
        .cliente
        .post(format!("{}/admin/metadata-keys", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({
            "id": Uuid::now_v7(),
            "public_key_x25519_b64": B64.encode(par.publica().as_bytes()),
            "fingerprint": "tercera",
            "destinatarios": [],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409, "una tercera clave compartida activa simultánea debe fallar");
}

#[tokio::test]
async fn compartir_un_recurso_con_metadata_personal_falla_explicito() {
    let entorno = common::levantar().await;
    let alice = common::registrar(&entorno, "alice-mk@test.ellkan").await;
    let bob = common::registrar(&entorno, "bob-mk@test.ellkan").await;
    let sesion_alice = common::login(&entorno, &alice).await;
    common::login(&entorno, &bob).await;

    // Recurso creado SIN metadata_key_id -> queda `user_key` (default, mismo
    // comportamiento que Fase 0).
    let dek_bytes: [u8; 32] = ellkan_crypto::aleatoriedad::bytes_aleatorios();
    let dek_secreta = SecretBox::new(Box::new(dek_bytes));
    let resource_id = Uuid::now_v7();
    let mut aad = Vec::new();
    aad.extend_from_slice(resource_id.as_bytes());
    aad.extend_from_slice(alice.user_id.as_bytes());

    let metadata_env = aead::cifrar(&dek_secreta, b"{}", &aad).unwrap();
    let secreto_env = aead::cifrar(&dek_secreta, b"{}", &aad).unwrap();
    let sealed_dek = sellado::sellar_dek(alice.x25519.publica(), &dek_secreta);

    let resp = entorno
        .cliente
        .post(format!("{}/resources", entorno.base))
        .bearer_auth(sesion_alice)
        .json(&json!({
            "id": resource_id,
            "resource_type_slug": "login-password",
            "metadata_ciphertext_b64": B64.encode(&metadata_env.ciphertext),
            "metadata_nonce_b64": B64.encode(metadata_env.nonce),
            "sealed_dek_b64": B64.encode(&sealed_dek),
            "secret_ciphertext_b64": B64.encode(&secreto_env.ciphertext),
            "secret_nonce_b64": B64.encode(secreto_env.nonce),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let sealed_dek_bob = sellado::sellar_dek(bob.x25519.publica(), &dek_secreta);
    let resp = entorno
        .cliente
        .post(format!("{}/resources/{resource_id}/share", entorno.base))
        .bearer_auth(sesion_alice)
        .json(&json!({
            "recipient_user_id": bob.user_id,
            "sealed_dek_b64": B64.encode(&sealed_dek_bob),
            "secret_ciphertext_b64": B64.encode(&secreto_env.ciphertext),
            "secret_nonce_b64": B64.encode(secreto_env.nonce),
            "level": "read",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "un recurso con metadata personal no debe poder compartirse");
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["error"]["code"], "METADATA_PERSONAL_NO_COMPARTIBLE");
}

#[tokio::test]
async fn crear_recurso_con_metadata_key_inexistente_falla() {
    let entorno = common::levantar().await;
    let alice = common::registrar(&entorno, "alice-mk-2@test.ellkan").await;
    let sesion_alice = common::login(&entorno, &alice).await;

    let dek_bytes: [u8; 32] = ellkan_crypto::aleatoriedad::bytes_aleatorios();
    let dek_secreta = SecretBox::new(Box::new(dek_bytes));
    let resource_id = Uuid::now_v7();
    let mut aad = Vec::new();
    aad.extend_from_slice(resource_id.as_bytes());
    aad.extend_from_slice(alice.user_id.as_bytes());
    let metadata_env = aead::cifrar(&dek_secreta, b"{}", &aad).unwrap();
    let secreto_env = aead::cifrar(&dek_secreta, b"{}", &aad).unwrap();
    let sealed_dek = sellado::sellar_dek(alice.x25519.publica(), &dek_secreta);

    let resp = entorno
        .cliente
        .post(format!("{}/resources", entorno.base))
        .bearer_auth(sesion_alice)
        .json(&json!({
            "id": resource_id,
            "resource_type_slug": "login-password",
            "metadata_ciphertext_b64": B64.encode(&metadata_env.ciphertext),
            "metadata_nonce_b64": B64.encode(metadata_env.nonce),
            "sealed_dek_b64": B64.encode(&sealed_dek),
            "secret_ciphertext_b64": B64.encode(&secreto_env.ciphertext),
            "secret_nonce_b64": B64.encode(secreto_env.nonce),
            "metadata_key_id": Uuid::now_v7(),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}
