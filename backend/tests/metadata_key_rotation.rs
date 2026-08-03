// Autor: Athan Espinoza

//! F-33: durante una rotación activa se puede seguir leyendo con la
//! saliente, crear con la entrante, migrar un recurso vía
//! `rekey-metadata`, y una segunda rotación simultánea falla explícito.

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
    let resp = entorno
        .cliente
        .post(format!("{}/admin/metadata-keys", entorno.base))
        .bearer_auth(sesion_admin)
        .json(&json!({
            "id": Uuid::now_v7(),
            "public_key_x25519_b64": B64.encode(par.publica().as_bytes()),
            "fingerprint": "fp",
            "destinatarios": [],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cuerpo: Value = resp.json().await.unwrap();
    cuerpo["id"].as_str().unwrap().parse().unwrap()
}

async fn crear_recurso_compartible(
    entorno: &common::Entorno,
    sesion: Uuid,
    owner: &common::Usuario,
    metadata_key_id: Uuid,
) -> Uuid {
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
            "metadata_key_id": metadata_key_id,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "crear recurso compartible debería devolver 200");
    resource_id
}

#[tokio::test]
async fn segunda_rotacion_simultanea_falla_explicito() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin-rot-1@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion = common::login(&entorno, &admin).await;

    let saliente_id = crear_metadata_key(&entorno, sesion).await;
    // Un recurso todavía referenciando la saliente evita que el job de
    // background la expire de inmediato (0 pendientes = migración trivial),
    // que es exactamente lo que rompería el escenario que este test cubre.
    crear_recurso_compartible(&entorno, sesion, &admin, saliente_id).await;

    let par = KeypairAcuerdo::generar();
    let resp = entorno
        .cliente
        .post(format!("{}/admin/metadata-keys/rotate", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({
            "id": Uuid::now_v7(),
            "public_key_x25519_b64": B64.encode(par.publica().as_bytes()),
            "fingerprint": "entrante",
            "destinatarios": [],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "primera rotación debe aceptarse");

    let par2 = KeypairAcuerdo::generar();
    let resp = entorno
        .cliente
        .post(format!("{}/admin/metadata-keys/rotate", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({
            "id": Uuid::now_v7(),
            "public_key_x25519_b64": B64.encode(par2.publica().as_bytes()),
            "fingerprint": "otra-entrante",
            "destinatarios": [],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409, "una segunda rotación mientras la primera sigue en curso debe fallar");
}

#[tokio::test]
async fn rotar_sin_ninguna_clave_activa_falla_explicito() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin-rot-2@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion = common::login(&entorno, &admin).await;

    let par = KeypairAcuerdo::generar();
    let resp = entorno
        .cliente
        .post(format!("{}/admin/metadata-keys/rotate", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({
            "id": Uuid::now_v7(),
            "public_key_x25519_b64": B64.encode(par.publica().as_bytes()),
            "fingerprint": "x",
            "destinatarios": [],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "rotar sin ninguna clave compartida activa no tiene sentido");
}

#[tokio::test]
async fn rotacion_completa_expira_la_saliente_y_migrar_via_rekey_funciona() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin-rot-3@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion = common::login(&entorno, &admin).await;

    let saliente_id = crear_metadata_key(&entorno, sesion).await;
    let recurso_id = crear_recurso_compartible(&entorno, sesion, &admin, saliente_id).await;

    let par_entrante = KeypairAcuerdo::generar();
    let entrante_id = Uuid::now_v7();
    let resp = entorno
        .cliente
        .post(format!("{}/admin/metadata-keys/rotate", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({
            "id": entrante_id,
            "public_key_x25519_b64": B64.encode(par_entrante.publica().as_bytes()),
            "fingerprint": "entrante",
            "destinatarios": [],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // --- Durante la rotación: el status refleja 1 pendiente ---
    let resp = entorno
        .cliente
        .get(format!("{}/admin/metadata-keys/rotation-status", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    let estado: Value = resp.json().await.unwrap();
    assert_eq!(estado["activa"], true);
    assert_eq!(estado["saliente_id"], json!(saliente_id));
    assert_eq!(estado["entrante_id"], json!(entrante_id));
    assert_eq!(estado["total_al_iniciar"], 1);
    assert_eq!(estado["pendientes"], 1);

    // --- Se puede seguir leyendo el recurso con la saliente todavía vigente ---
    let resp = entorno
        .cliente
        .get(format!("{}/resources/{recurso_id}", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let recurso: Value = resp.json().await.unwrap();
    assert_eq!(recurso["metadata_key_id"], json!(saliente_id));

    // --- Se puede crear un recurso nuevo directamente con la entrante ---
    let _otro = crear_recurso_compartible(&entorno, sesion, &admin, entrante_id).await;

    // --- Migra el recurso existente hacia la entrante (F-33) ---
    let resp = entorno
        .cliente
        .post(format!("{}/resources/{recurso_id}/rekey-metadata", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({
            "expected_current_metadata_key_id": saliente_id,
            "new_metadata_key_id": entrante_id,
            "metadata_ciphertext_b64": "eA==",
            "metadata_nonce_b64": "eA==",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // --- Repetir el mismo rekey (ya migrado) falla explícito, no pisa nada ---
    let resp = entorno
        .cliente
        .post(format!("{}/resources/{recurso_id}/rekey-metadata", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({
            "expected_current_metadata_key_id": saliente_id,
            "new_metadata_key_id": entrante_id,
            "metadata_ciphertext_b64": "eA==",
            "metadata_nonce_b64": "eA==",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409, "un rekey sobre una fila que ya no apunta a la clave esperada debe fallar");

    // --- El job de background detecta 0 pendientes y expira la saliente ---
    let mut expirada = false;
    for _ in 0..30 {
        let resp = entorno
            .cliente
            .get(format!("{}/admin/metadata-keys/rotation-status", entorno.base))
            .bearer_auth(sesion)
            .send()
            .await
            .unwrap();
        let estado: Value = resp.json().await.unwrap();
        if estado["activa"] == json!(false) {
            expirada = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    assert!(expirada, "la saliente debería quedar expirada una vez que 0 recursos la referencian");

    // --- Iniciar otra rotación ahora sí funciona (sólo 1 activa de nuevo) ---
    let par_otra = KeypairAcuerdo::generar();
    let resp = entorno
        .cliente
        .post(format!("{}/admin/metadata-keys/rotate", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({
            "id": Uuid::now_v7(),
            "public_key_x25519_b64": B64.encode(par_otra.publica().as_bytes()),
            "fingerprint": "otra-mas",
            "destinatarios": [],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}
