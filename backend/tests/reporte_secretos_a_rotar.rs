// Autor: Athan Espinoza

//! spec/15 §7 (#56): reporte de «secretos a rotar» — lo que cuentas ya
//! desactivadas siguen teniendo descifrable, con sus dueños activos.

mod common;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ellkan_crypto::{aead, sellado};
use secrecy::SecretBox;
use serde_json::{Value, json};
use uuid::Uuid;

async fn crear_recurso(entorno: &common::Entorno, sesion: Uuid, owner: &common::Usuario, tipo: &str) -> Uuid {
    let dek = SecretBox::new(Box::new(ellkan_crypto::aleatoriedad::bytes_aleatorios::<32>()));
    let id = Uuid::now_v7();
    let mut aad = Vec::new();
    aad.extend_from_slice(id.as_bytes());
    aad.extend_from_slice(owner.user_id.as_bytes());
    let metadata = aead::cifrar(&dek, b"{}", &aad).unwrap();
    let cifrado = aead::cifrar(&dek, b"{}", &aad).unwrap();
    let resp = entorno
        .cliente
        .post(format!("{}/resources", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({
            "id": id,
            "resource_type_slug": tipo,
            "metadata_ciphertext_b64": B64.encode(&metadata.ciphertext),
            "metadata_nonce_b64": B64.encode(metadata.nonce),
            "sealed_dek_b64": B64.encode(sellado::sellar_dek(owner.x25519.publica(), &dek)),
            "secret_ciphertext_b64": B64.encode(&cifrado.ciphertext),
            "secret_nonce_b64": B64.encode(cifrado.nonce),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);
    id
}

#[tokio::test]
async fn lista_lo_que_tienen_las_cuentas_desactivadas() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let s_admin = common::login(&entorno, &admin).await;
    let ana = common::registrar(&entorno, "ana@test.ellkan").await;
    let s_ana = common::login(&entorno, &ana).await;
    let beto = common::registrar(&entorno, "beto@test.ellkan").await;
    let s_beto = common::login(&entorno, &beto).await;

    let de_ana = crear_recurso(&entorno, s_ana, &ana, "ssh").await;
    let de_beto = crear_recurso(&entorno, s_beto, &beto, "login-password").await;
    // Beto también tiene el sobre del SSH de Ana (se lo compartió).
    let sobre: (Vec<u8>, Vec<u8>, Vec<u8>) =
        sqlx::query_as("select sealed_dek, secret_ciphertext, secret_nonce from secret_envelopes where resource_id = $1")
            .bind(de_ana)
            .fetch_one(&entorno.pool)
            .await
            .unwrap();
    sqlx::query(
        "insert into secret_envelopes (resource_id, user_id, sealed_dek, secret_ciphertext, secret_nonce) values ($1, $2, $3, $4, $5)",
    )
    .bind(de_ana)
    .bind(beto.user_id)
    .bind(&sobre.0)
    .bind(&sobre.1)
    .bind(&sobre.2)
    .execute(&entorno.pool)
    .await
    .unwrap();

    let reporte = |entorno: &common::Entorno| {
        let url = format!("{}/admin/reports/secrets_to_rotate", entorno.base);
        let cliente = entorno.cliente.clone();
        async move {
            let resp = cliente.get(url).bearer_auth(s_admin).send().await.unwrap();
            assert_eq!(resp.status(), 200);
            resp.json::<Value>().await.unwrap()
        }
    };
    assert_eq!(reporte(&entorno).await["items"], json!([]), "nadie desactivado, nada que rotar");

    sqlx::query("update users set active = false where id = $1")
        .bind(beto.user_id)
        .execute(&entorno.pool)
        .await
        .unwrap();
    let r = reporte(&entorno).await;
    assert_eq!(r["report_id"], "secrets_to_rotate");
    let items = r["items"].as_array().unwrap();
    assert_eq!(items.len(), 2, "{r}");
    let ssh = items.iter().find(|i| i["resource_id"] == de_ana.to_string()).unwrap();
    assert_eq!(ssh["high_priority"], true);
    assert_eq!(ssh["owners"], json!(["ana@test.ellkan"]));
    assert_eq!(ssh["deactivated_users"], json!(["beto@test.ellkan"]));
    let propio = items.iter().find(|i| i["resource_id"] == de_beto.to_string()).unwrap();
    assert_eq!(propio["high_priority"], false);
    assert_eq!(propio["owners"], json!([]), "el único dueño es el desactivado");

    // Sólo admins.
    let resp = entorno
        .cliente
        .get(format!("{}/admin/reports/secrets_to_rotate", entorno.base))
        .bearer_auth(s_ana)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}
