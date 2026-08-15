// Autor: Athan Espinoza

//! F-10: criterios de aceptación literales — 403 al crear un tag compartido
//! sin ser admin, filtrar por tag devuelve el conjunto esperado, un tag
//! personal de A nunca aparece para B.

mod common;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ellkan_crypto::aead;
use ellkan_crypto::sellado;
use secrecy::SecretBox;
use serde_json::{json, Value};
use uuid::Uuid;

async fn crear_recurso_de_prueba(entorno: &common::Entorno, sesion: Uuid, owner: &common::Usuario) -> Uuid {
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
    resource_id
}

#[tokio::test]
async fn usuario_no_admin_no_puede_crear_tag_compartido() {
    let entorno = common::levantar().await;
    let alice = common::registrar(&entorno, "alice-tags@test.ellkan").await;
    let sesion = common::login(&entorno, &alice).await;

    let resp = entorno
        .cliente
        .post(format!("{}/tags", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({ "id": Uuid::now_v7(), "name": "produccion", "is_shared": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Un tag personal sí funciona sin ser admin.
    let resp = entorno
        .cliente
        .post(format!("{}/tags", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({ "id": Uuid::now_v7(), "name": "mio", "is_shared": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn tag_personal_de_alice_nunca_aparece_para_bob() {
    let entorno = common::levantar().await;
    let alice = common::registrar(&entorno, "alice-tags-2@test.ellkan").await;
    let bob = common::registrar(&entorno, "bob-tags-2@test.ellkan").await;
    let sesion_alice = common::login(&entorno, &alice).await;
    let sesion_bob = common::login(&entorno, &bob).await;

    entorno
        .cliente
        .post(format!("{}/tags", entorno.base))
        .bearer_auth(sesion_alice)
        .json(&json!({ "id": Uuid::now_v7(), "name": "secreto-de-alice", "is_shared": false }))
        .send()
        .await
        .unwrap();

    let resp = entorno
        .cliente
        .get(format!("{}/tags", entorno.base))
        .bearer_auth(sesion_bob)
        .send()
        .await
        .unwrap();
    let tags_de_bob: Value = resp.json().await.unwrap();
    assert!(
        tags_de_bob.as_array().unwrap().iter().all(|t| t["name"] != json!("secreto-de-alice")),
        "el tag personal de Alice no debe aparecer en el listado de Bob"
    );
}

#[tokio::test]
async fn filtrar_recursos_por_tag_devuelve_el_conjunto_esperado() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin-tags-3@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    let recurso_a = crear_recurso_de_prueba(&entorno, sesion_admin, &admin).await;
    let recurso_b = crear_recurso_de_prueba(&entorno, sesion_admin, &admin).await;

    let tag_id = Uuid::now_v7();
    let resp = entorno
        .cliente
        .post(format!("{}/tags", entorno.base))
        .bearer_auth(sesion_admin)
        .json(&json!({ "id": tag_id, "name": "produccion", "is_shared": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = entorno
        .cliente
        .post(format!("{}/resources/{recurso_a}/tags/{tag_id}", entorno.base))
        .bearer_auth(sesion_admin)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "aplicar un tag compartido ya existente no exige admin");

    let resp = entorno
        .cliente
        .get(format!("{}/resources?tag_id={tag_id}", entorno.base))
        .bearer_auth(sesion_admin)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let recursos: Value = resp.json().await.unwrap();
    let ids: Vec<&str> = recursos.as_array().unwrap().iter().map(|r| r["id"].as_str().unwrap()).collect();
    assert_eq!(ids, vec![recurso_a.to_string()], "sólo el recurso etiquetado debe aparecer");
    assert!(!ids.contains(&recurso_b.to_string().as_str()));

    // --- Quitar el tag lo saca del filtro ---
    let resp = entorno
        .cliente
        .delete(format!("{}/resources/{recurso_a}/tags/{tag_id}", entorno.base))
        .bearer_auth(sesion_admin)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = entorno
        .cliente
        .get(format!("{}/resources?tag_id={tag_id}", entorno.base))
        .bearer_auth(sesion_admin)
        .send()
        .await
        .unwrap();
    let recursos: Value = resp.json().await.unwrap();
    assert_eq!(recursos.as_array().unwrap().len(), 0);
}
