// Autor: Athan Espinoza

//! Módulo 3 (compartir en lote): `POST /resources/share-bulk` — mismo
//! envelope por-destinatario que el share 1×1 de siempre, loopeado.
//! Verifica que N recursos se comparten en una sola llamada, que el
//! destinatario puede leer los secretos, y que un ítem inválido no aborta
//! el resto del lote (tolerante a fallos parciales, mismo criterio que la
//! carga CSV de grupos).

mod common;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ellkan_crypto::aead;
use ellkan_crypto::claves::KeypairAcuerdo;
use ellkan_crypto::sellado;
use secrecy::SecretBox;
use serde_json::{json, Value};
use uuid::Uuid;

async fn crear_metadata_key(entorno: &common::Entorno, sesion_admin: Uuid) -> Uuid {
    let par = KeypairAcuerdo::generar();
    let id = Uuid::now_v7();
    let resp = entorno
        .cliente
        .post(format!("{}/admin/metadata-keys", entorno.base))
        .bearer_auth(sesion_admin)
        .json(&json!({
            "id": id,
            "public_key_x25519_b64": B64.encode(par.publica().as_bytes()),
            "fingerprint": "fp-lote",
            "destinatarios": [],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    id
}

struct RecursoDePrueba {
    id: Uuid,
    dek: SecretBox<[u8; 32]>,
    secreto_ciphertext: Vec<u8>,
    secreto_nonce: Vec<u8>,
}

async fn crear_recurso_compartible(
    entorno: &common::Entorno,
    sesion_owner: Uuid,
    owner: &common::Usuario,
    metadata_key_id: Uuid,
) -> RecursoDePrueba {
    let dek_bytes: [u8; 32] = ellkan_crypto::aleatoriedad::bytes_aleatorios();
    let dek = SecretBox::new(Box::new(dek_bytes));
    let resource_id = Uuid::now_v7();
    let mut aad = Vec::new();
    aad.extend_from_slice(resource_id.as_bytes());
    aad.extend_from_slice(owner.user_id.as_bytes());

    let metadata_env = aead::cifrar(&dek, br#"{"name":"lote"}"#, &aad).unwrap();
    let secreto_env = aead::cifrar(&dek, br#"{"password":"pw-lote"}"#, &aad).unwrap();
    let sealed_dek = sellado::sellar_dek(owner.x25519.publica(), &dek);

    let resp = entorno
        .cliente
        .post(format!("{}/resources", entorno.base))
        .bearer_auth(sesion_owner)
        .json(&json!({
            "id": resource_id,
            "resource_type_slug": "login-password",
            "metadata_ciphertext_b64": B64.encode(&metadata_env.ciphertext),
            "metadata_nonce_b64": B64.encode(metadata_env.nonce),
            "sealed_dek_b64": B64.encode(&sealed_dek),
            "secret_ciphertext_b64": B64.encode(&secreto_env.ciphertext),
            "secret_nonce_b64": B64.encode(secreto_env.nonce),
            "metadata_key_id": metadata_key_id,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    RecursoDePrueba { id: resource_id, dek, secreto_ciphertext: secreto_env.ciphertext, secreto_nonce: secreto_env.nonce.to_vec() }
}

#[tokio::test]
async fn share_bulk_comparte_n_recursos_y_tolera_un_item_invalido() {
    let entorno = common::levantar().await;
    let alice = common::registrar(&entorno, "alice-lote@test.ellkan").await;
    let bob = common::registrar(&entorno, "bob-lote@test.ellkan").await;
    let sesion_alice = common::login(&entorno, &alice).await;
    let sesion_bob = common::login(&entorno, &bob).await;
    common::promover_admin(&entorno.pool, alice.user_id).await;

    let metadata_key_id = crear_metadata_key(&entorno, sesion_alice).await;
    let r1 = crear_recurso_compartible(&entorno, sesion_alice, &alice, metadata_key_id).await;
    let r2 = crear_recurso_compartible(&entorno, sesion_alice, &alice, metadata_key_id).await;

    let publica_bob = *bob.x25519.publica();
    let item_valido = |r: &RecursoDePrueba| {
        json!({
            "resource_id": r.id,
            "recipient_user_id": bob.user_id,
            "sealed_dek_b64": B64.encode(sellado::sellar_dek(&publica_bob, &r.dek)),
            "secret_ciphertext_b64": B64.encode(&r.secreto_ciphertext),
            "secret_nonce_b64": B64.encode(&r.secreto_nonce),
            "level": "read",
        })
    };

    // Tercer ítem deliberadamente inválido — un `resource_id` que no existe,
    // para confirmar que no aborta los otros dos.
    let item_invalido = json!({
        "resource_id": Uuid::now_v7(),
        "recipient_user_id": bob.user_id,
        "sealed_dek_b64": B64.encode(sellado::sellar_dek(&publica_bob, &r1.dek)),
        "secret_ciphertext_b64": B64.encode(&r1.secreto_ciphertext),
        "secret_nonce_b64": B64.encode(&r1.secreto_nonce),
        "level": "read",
    });

    let resp = entorno
        .cliente
        .post(format!("{}/resources/share-bulk", entorno.base))
        .bearer_auth(sesion_alice)
        .json(&json!({ "items": [item_valido(&r1), item_valido(&r2), item_invalido] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let cuerpo: Value = resp.json().await.unwrap();
    let resultados = cuerpo["resultados"].as_array().unwrap();
    assert_eq!(resultados.len(), 3);
    let ok = resultados.iter().filter(|r| r["error"].is_null()).count();
    let con_error = resultados.iter().filter(|r| !r["error"].is_null()).count();
    assert_eq!(ok, 2, "los dos ítems válidos deberían aplicarse");
    assert_eq!(con_error, 1, "el ítem con resource_id inexistente debería quedar registrado como error");

    // Bob ya puede leer los dos recursos válidos.
    for r in [&r1, &r2] {
        let resp = entorno
            .cliente
            .get(format!("{}/resources/{}/secret", entorno.base, r.id))
            .bearer_auth(sesion_bob)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "bob debería poder leer el recurso compartido en el lote");
    }
}
