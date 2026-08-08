// Autor: Athan Espinoza

//! F-07: editar un recurso ya creado — concurrencia optimista real
//! (`If-Match`) y re-sellado de todos los destinatarios actuales, no sólo
//! del editor.

mod common;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ellkan_crypto::aead;
use ellkan_crypto::sellado;
use secrecy::SecretBox;
use serde_json::{json, Value};
use uuid::Uuid;

fn aad_de(resource_id: Uuid, created_by: Uuid) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(resource_id.as_bytes());
    aad.extend_from_slice(created_by.as_bytes());
    aad
}

struct RecursoDePrueba {
    id: Uuid,
    updated_at: String,
}

async fn crear_recurso_personal(entorno: &common::Entorno, sesion: Uuid, owner: &common::Usuario) -> RecursoDePrueba {
    let dek_bytes: [u8; 32] = ellkan_crypto::aleatoriedad::bytes_aleatorios();
    let dek = SecretBox::new(Box::new(dek_bytes));
    let resource_id = Uuid::now_v7();
    let aad = aad_de(resource_id, owner.user_id);
    let metadata_env = aead::cifrar(&dek, br#"{"name":"original"}"#, &aad).unwrap();
    let secreto_env = aead::cifrar(&dek, br#"{"password":"original-pw"}"#, &aad).unwrap();
    let sealed_dek = sellado::sellar_dek(owner.x25519.publica(), &dek);

    let resp = entorno
        .cliente
        .post(format!("{}/resources", entorno.base))
        .bearer_auth(sesion)
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
    let cuerpo: Value = resp.json().await.unwrap();
    RecursoDePrueba { id: resource_id, updated_at: cuerpo["updated_at"].as_str().unwrap().to_string() }
}

fn armar_put_body(owner: &common::Usuario, resource_id: Uuid, dek_nueva: &SecretBox<[u8; 32]>) -> Value {
    let aad = aad_de(resource_id, owner.user_id);
    let metadata_env = aead::cifrar(dek_nueva, br#"{"name":"editado"}"#, &aad).unwrap();
    let secreto_env = aead::cifrar(dek_nueva, br#"{"password":"nueva-pw"}"#, &aad).unwrap();
    let sealed_dek = sellado::sellar_dek(owner.x25519.publica(), dek_nueva);
    json!({
        "metadata_ciphertext_b64": B64.encode(&metadata_env.ciphertext),
        "metadata_nonce_b64": B64.encode(metadata_env.nonce),
        "envelopes": [{
            "recipient_user_id": owner.user_id,
            "sealed_dek_b64": B64.encode(&sealed_dek),
            "secret_ciphertext_b64": B64.encode(&secreto_env.ciphertext),
            "secret_nonce_b64": B64.encode(secreto_env.nonce),
        }]
    })
}

#[tokio::test]
async fn editar_con_if_match_correcto_actualiza_metadata_y_resella_para_el_destinatario() {
    let entorno = common::levantar().await;
    let owner = common::registrar(&entorno, "editar-owner@test.ellkan").await;
    let sesion = common::login(&entorno, &owner).await;
    let recurso = crear_recurso_personal(&entorno, sesion, &owner).await;

    let dek_bytes: [u8; 32] = ellkan_crypto::aleatoriedad::bytes_aleatorios();
    let dek_nueva = SecretBox::new(Box::new(dek_bytes));
    let body = armar_put_body(&owner, recurso.id, &dek_nueva);

    let resp = entorno
        .cliente
        .put(format!("{}/resources/{}", entorno.base, recurso.id))
        .bearer_auth(sesion)
        .header("If-Match", &recurso.updated_at)
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(status, 200, "{cuerpo:?}");
    assert_ne!(cuerpo["updated_at"].as_str().unwrap(), recurso.updated_at, "updated_at debe avanzar tras la edición");

    // El GET posterior devuelve la metadata/secreto nuevos.
    let get = entorno
        .cliente
        .get(format!("{}/resources/{}", entorno.base, recurso.id))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    let cuerpo_get: Value = get.json().await.unwrap();
    assert_eq!(cuerpo_get["metadata_ciphertext_b64"], body["metadata_ciphertext_b64"]);

    let secreto = entorno
        .cliente
        .get(format!("{}/resources/{}/secret", entorno.base, recurso.id))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    let cuerpo_secreto: Value = secreto.json().await.unwrap();
    assert_eq!(cuerpo_secreto["secret_ciphertext_b64"], body["envelopes"][0]["secret_ciphertext_b64"]);
}

#[tokio::test]
async fn editar_con_if_match_vencido_falla_con_409_sin_aplicar_nada() {
    let entorno = common::levantar().await;
    let owner = common::registrar(&entorno, "editar-conflicto@test.ellkan").await;
    let sesion = common::login(&entorno, &owner).await;
    let recurso = crear_recurso_personal(&entorno, sesion, &owner).await;

    let dek_bytes: [u8; 32] = ellkan_crypto::aleatoriedad::bytes_aleatorios();
    let dek_nueva = SecretBox::new(Box::new(dek_bytes));
    let body = armar_put_body(&owner, recurso.id, &dek_nueva);

    // `If-Match` con una fecha claramente vieja/incorrecta — nunca coincide
    // con el `updated_at` real de la fila recién creada.
    let resp = entorno
        .cliente
        .put(format!("{}/resources/{}", entorno.base, recurso.id))
        .bearer_auth(sesion)
        .header("If-Match", "2020-01-01T00:00:00Z")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409, "If-Match desactualizado debe rechazarse, no aplicar la edición en silencio");

    // La metadata original sigue intacta.
    let get = entorno
        .cliente
        .get(format!("{}/resources/{}", entorno.base, recurso.id))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    let cuerpo_get: Value = get.json().await.unwrap();
    assert_ne!(cuerpo_get["metadata_ciphertext_b64"], body["metadata_ciphertext_b64"]);
}

#[tokio::test]
async fn editar_sin_header_if_match_falla_explicito() {
    let entorno = common::levantar().await;
    let owner = common::registrar(&entorno, "editar-sin-header@test.ellkan").await;
    let sesion = common::login(&entorno, &owner).await;
    let recurso = crear_recurso_personal(&entorno, sesion, &owner).await;

    let dek_bytes: [u8; 32] = ellkan_crypto::aleatoriedad::bytes_aleatorios();
    let dek_nueva = SecretBox::new(Box::new(dek_bytes));
    let body = armar_put_body(&owner, recurso.id, &dek_nueva);

    let resp = entorno
        .cliente
        .put(format!("{}/resources/{}", entorno.base, recurso.id))
        .bearer_auth(sesion)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "sin If-Match no debería intentar aplicar nada");
}

#[tokio::test]
async fn usuario_sin_permiso_no_puede_editar() {
    let entorno = common::levantar().await;
    let owner = common::registrar(&entorno, "editar-ajeno-owner@test.ellkan").await;
    let sesion_owner = common::login(&entorno, &owner).await;
    let recurso = crear_recurso_personal(&entorno, sesion_owner, &owner).await;

    let otro = common::registrar(&entorno, "editar-ajeno-otro@test.ellkan").await;
    let sesion_otro = common::login(&entorno, &otro).await;

    let dek_bytes: [u8; 32] = ellkan_crypto::aleatoriedad::bytes_aleatorios();
    let dek_nueva = SecretBox::new(Box::new(dek_bytes));
    let body = armar_put_body(&owner, recurso.id, &dek_nueva);

    let resp = entorno
        .cliente
        .put(format!("{}/resources/{}", entorno.base, recurso.id))
        .bearer_auth(sesion_otro)
        .header("If-Match", &recurso.updated_at)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn recipients_devuelve_al_unico_destinatario_de_un_recurso_personal() {
    let entorno = common::levantar().await;
    let owner = common::registrar(&entorno, "recipients-owner@test.ellkan").await;
    let sesion = common::login(&entorno, &owner).await;
    let recurso = crear_recurso_personal(&entorno, sesion, &owner).await;

    let resp = entorno
        .cliente
        .get(format!("{}/resources/{}/recipients", entorno.base, recurso.id))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cuerpo: Value = resp.json().await.unwrap();
    let lista = cuerpo.as_array().unwrap();
    assert_eq!(lista.len(), 1);
    assert_eq!(lista[0]["user_id"].as_str().unwrap(), owner.user_id.to_string());
    assert_eq!(lista[0]["public_key_x25519_b64"].as_str().unwrap(), B64.encode(owner.x25519.publica().as_bytes()));
}
