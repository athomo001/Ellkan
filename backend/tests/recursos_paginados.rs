// Autor: Athan Espinoza

//! QA-12: `GET /resources?limit=&after=` — paginación por cursor opcional.
//! Sin `limit`, la lista entera como antes; con él, páginas que juntas dan
//! exactamente la lista entera, sin repetir ni perder ninguno.

mod common;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ellkan_crypto::{aead, sellado};
use secrecy::SecretBox;
use serde_json::{Value, json};
use uuid::Uuid;

async fn crear_recurso(entorno: &common::Entorno, sesion: Uuid, owner: &common::Usuario) -> Uuid {
    let dek = SecretBox::new(Box::new(ellkan_crypto::aleatoriedad::bytes_aleatorios::<32>()));
    let id = Uuid::now_v7();
    let mut aad = id.as_bytes().to_vec();
    aad.extend_from_slice(owner.user_id.as_bytes());
    let metadata = aead::cifrar(&dek, br#"{"name":"x"}"#, &aad).unwrap();
    let secreto = aead::cifrar(&dek, br#"{"password":"x"}"#, &aad).unwrap();
    let resp = entorno
        .cliente
        .post(format!("{}/resources", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({
            "id": id,
            "resource_type_slug": "login-password",
            "metadata_ciphertext_b64": B64.encode(&metadata.ciphertext),
            "metadata_nonce_b64": B64.encode(metadata.nonce),
            "sealed_dek_b64": B64.encode(sellado::sellar_dek(owner.x25519.publica(), &dek)),
            "secret_ciphertext_b64": B64.encode(&secreto.ciphertext),
            "secret_nonce_b64": B64.encode(secreto.nonce),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    id
}

/// `(ids de la página, cursor siguiente)`.
async fn pagina(entorno: &common::Entorno, sesion: Uuid, consulta: &str) -> (Vec<Uuid>, Option<String>) {
    let resp = entorno
        .cliente
        .get(format!("{}/resources{consulta}", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cursor = resp.headers().get("x-ellkan-next-cursor").map(|v| v.to_str().unwrap().to_string());
    let cuerpo: Vec<Value> = resp.json().await.unwrap();
    let ids = cuerpo.iter().map(|r| r["id"].as_str().unwrap().parse().unwrap()).collect();
    (ids, cursor)
}

#[tokio::test]
async fn las_paginas_juntas_son_la_lista_entera() {
    let entorno = common::levantar().await;
    let alice = common::registrar(&entorno, "alice@test.ellkan").await;
    let sesion = common::login(&entorno, &alice).await;
    for _ in 0..7 {
        crear_recurso(&entorno, sesion, &alice).await;
    }

    // Sin `limit`: todo, sin cabecera (clientes anteriores).
    let (todos, cursor) = pagina(&entorno, sesion, "").await;
    assert_eq!(todos.len(), 7);
    assert!(cursor.is_none());

    // Páginas de 3: 3 + 3 + 1, y la última sin cursor.
    let mut juntos = Vec::new();
    let mut consulta = "?limit=3".to_string();
    let mut paginas = 0;
    loop {
        let (ids, cursor) = pagina(&entorno, sesion, &consulta).await;
        paginas += 1;
        juntos.extend(ids);
        match cursor {
            Some(c) => consulta = format!("?limit=3&after={c}"),
            None => break,
        }
    }
    assert_eq!(paginas, 3);
    let mut esperado = todos.clone();
    esperado.sort();
    assert_eq!(juntos, esperado, "ordenadas por id, sin repetir ni perder");

    // Una página exacta (limit = total) no deja cursor colgando.
    let (ids, cursor) = pagina(&entorno, sesion, "?limit=7").await;
    assert_eq!(ids.len(), 7);
    assert!(cursor.is_none());

    // Fuera de rango: 400.
    for mal in ["?limit=0", "?limit=501"] {
        let resp = entorno
            .cliente
            .get(format!("{}/resources{mal}", entorno.base))
            .bearer_auth(sesion)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 400, "{mal}");
    }
}
