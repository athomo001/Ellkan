// Autor: Athan Espinoza

//! QA-03/QA-15: `POST /auth/key-material` no revela si una cuenta existe —
//! para un email sin cuenta responde siempre lo mismo, con la misma forma
//! que el material real.

mod common;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Value, json};

async fn material(entorno: &common::Entorno, email: &str) -> Value {
    let resp = entorno
        .cliente
        .post(format!("{}/auth/key-material", entorno.base))
        .json(&json!({ "email": email }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    resp.json().await.unwrap()
}

fn largos(cuerpo: &Value) -> (usize, usize, usize) {
    let largo = |campo: &str| B64.decode(cuerpo[campo].as_str().unwrap()).unwrap().len();
    (
        largo("encrypted_private_key_blob_b64"),
        largo("private_key_nonce_b64"),
        largo("kdf_salt_b64"),
    )
}

#[tokio::test]
async fn key_material_no_revela_existencia() {
    let entorno = common::levantar().await;
    let usuario = common::registrar(&entorno, "real-key-material@test.ellkan").await;

    let falso_1 = material(&entorno, "nadie-key-material@test.ellkan").await;
    let falso_2 = material(&entorno, "nadie-key-material@test.ellkan").await;
    assert_eq!(
        falso_1, falso_2,
        "dos consultas por el mismo email inexistente deben ser idénticas"
    );

    let otro_falso = material(&entorno, "otro-nadie@test.ellkan").await;
    assert_ne!(
        falso_1, otro_falso,
        "emails distintos no deben compartir material"
    );

    let real_1 = material(&entorno, &usuario.email).await;
    let real_2 = material(&entorno, &usuario.email).await;
    assert_eq!(real_1, real_2);
    assert_eq!(
        largos(&falso_1),
        largos(&real_1),
        "misma forma que el material real"
    );
}
