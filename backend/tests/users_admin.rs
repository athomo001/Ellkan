// Autor: Athan Espinoza

//! F-40 (segundo y tercer checkbox): dry-run reporta bloqueos reales,
//! purgar sin cubrir el 100% falla entero, purgar con transferencia
//! completa funciona y no toca las filas de otros usuarios, y desactivar
//! invalida una sesión ya abierta de inmediato.

mod common;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ellkan_crypto::claves::KeypairAcuerdo;
use serde_json::{json, Value};

#[tokio::test]
async fn no_admin_no_puede_operar_sobre_otros_usuarios() {
    let entorno = common::levantar().await;
    let user = common::registrar(&entorno, "sin-admin@test.ellkan").await;
    let sesion = common::login(&entorno, &user).await;
    let victima = common::registrar(&entorno, "victima@test.ellkan").await;

    let resp = entorno
        .cliente
        .get(format!("{}/admin/users/{}/purge/dry-run", entorno.base, victima.user_id))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn dry_run_sin_bloqueos_y_purge_directo_borra_al_usuario() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;
    let victima = common::registrar(&entorno, "victima@test.ellkan").await;

    let resp = entorno
        .cliente
        .get(format!("{}/admin/users/{}/purge/dry-run", entorno.base, victima.user_id))
        .bearer_auth(sesion_admin)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["blocks_purge"], false);
    assert!(cuerpo["blocked_groups"].as_array().unwrap().is_empty());
    assert!(cuerpo["blocked_resources"].as_array().unwrap().is_empty());

    let resp = entorno
        .cliente
        .post(format!("{}/admin/users/{}/purge", entorno.base, victima.user_id))
        .bearer_auth(sesion_admin)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let existe: (bool,) = sqlx::query_as("select exists(select 1 from users where id = $1)")
        .bind(victima.user_id)
        .fetch_one(&entorno.pool)
        .await
        .unwrap();
    assert!(!existe.0, "el usuario purgado ya no debe existir");
}

#[tokio::test]
async fn purgar_unico_owner_sin_transferencia_falla_y_con_transferencia_funciona() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    let owner = common::registrar(&entorno, "owner@test.ellkan").await;
    let sesion_owner = common::login(&entorno, &owner).await;
    let colaborador = common::registrar(&entorno, "colaborador@test.ellkan").await;
    let sesion_colaborador = common::login(&entorno, &colaborador).await;

    // Metadata key compartida (F-06) — sólo un recurso `shared_key` puede
    // compartirse, requisito de `resources::compartir`.
    let par = KeypairAcuerdo::generar();
    let resp = entorno
        .cliente
        .post(format!("{}/admin/metadata-keys", entorno.base))
        .bearer_auth(sesion_admin)
        .json(&json!({
            "id": uuid::Uuid::now_v7(),
            "public_key_x25519_b64": B64.encode(par.publica().as_bytes()),
            "fingerprint": "fp-de-prueba",
            "destinatarios": [],
        }))
        .send()
        .await
        .unwrap();
    let metadata_key: Value = resp.json().await.unwrap();
    let metadata_key_id = metadata_key["id"].as_str().unwrap();

    // Recurso creado por `owner`, compartido con `colaborador` en `update`
    // (no Owner) — owner queda como único Owner, bloqueante.
    let resource_id = uuid::Uuid::now_v7();
    let resp = entorno
        .cliente
        .post(format!("{}/resources", entorno.base))
        .bearer_auth(sesion_owner)
        .json(&json!({
            "id": resource_id,
            "resource_type_slug": "login-password",
            "metadata_ciphertext_b64": "AAAA",
            "metadata_nonce_b64": "AAAA",
            "sealed_dek_b64": "AAAA",
            "secret_ciphertext_b64": "AAAA",
            "secret_nonce_b64": "AAAA",
            "metadata_key_id": metadata_key_id,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);

    let resp = entorno
        .cliente
        .post(format!("{}/resources/{resource_id}/share", entorno.base))
        .bearer_auth(sesion_owner)
        .json(&json!({
            "recipient_user_id": colaborador.user_id,
            "sealed_dek_b64": "AAAA",
            "secret_ciphertext_b64": "AAAA",
            "secret_nonce_b64": "AAAA",
            "level": "update",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);

    let resp = entorno
        .cliente
        .get(format!("{}/admin/users/{}/purge/dry-run", entorno.base, owner.user_id))
        .bearer_auth(sesion_admin)
        .send()
        .await
        .unwrap();
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["blocks_purge"], true);
    assert_eq!(cuerpo["blocked_resources"], json!([resource_id]));

    // Sin transferencia, la purga falla entera.
    let resp = entorno
        .cliente
        .post(format!("{}/admin/users/{}/purge", entorno.base, owner.user_id))
        .bearer_auth(sesion_admin)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);

    let existe: (bool,) = sqlx::query_as("select exists(select 1 from users where id = $1)")
        .bind(owner.user_id)
        .fetch_one(&entorno.pool)
        .await
        .unwrap();
    assert!(existe.0, "una purga fallida no debe borrar nada (todo o nada)");

    // Con transferencia al colaborador (que ya tenía acceso), funciona.
    let resp = entorno
        .cliente
        .post(format!("{}/admin/users/{}/purge", entorno.base, owner.user_id))
        .bearer_auth(sesion_admin)
        .json(&json!({
            "transfer": { "owners": [{ "resource_id": resource_id, "new_owner_user_id": colaborador.user_id }] }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);

    let existe: (bool,) = sqlx::query_as("select exists(select 1 from users where id = $1)")
        .bind(owner.user_id)
        .fetch_one(&entorno.pool)
        .await
        .unwrap();
    assert!(!existe.0);

    // El recurso sigue existiendo (co-owner ahora es el colaborador), y el
    // colaborador lo sigue viendo sin cambios en su propio envelope.
    let resp = entorno
        .cliente
        .get(format!("{}/resources/{resource_id}", entorno.base))
        .bearer_auth(sesion_colaborador)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "el recurso debe sobrevivir con el nuevo owner");
}

#[tokio::test]
async fn desactivar_invalida_una_sesion_ya_abierta_de_inmediato() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    let victima = common::registrar(&entorno, "victima@test.ellkan").await;
    let sesion_victima = common::login(&entorno, &victima).await;

    // La sesión funciona antes de desactivar.
    let resp = entorno
        .cliente
        .get(format!("{}/resources", entorno.base))
        .bearer_auth(sesion_victima)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = entorno
        .cliente
        .put(format!("{}/admin/users/{}", entorno.base, victima.user_id))
        .bearer_auth(sesion_admin)
        .json(&json!({ "active": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // La misma sesión, ya abierta, ahora falla — no sólo un login nuevo.
    let resp = entorno
        .cliente
        .get(format!("{}/resources", entorno.base))
        .bearer_auth(sesion_victima)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "una sesión abierta debe invalidarse de inmediato al desactivar");

    // Reactivar deja al usuario operable de nuevo (verificado a nivel de
    // política, no repitiendo el login completo acá — el dispositivo ya
    // conocido de `victima` saltearía el paso de verificación que
    // `common::login` da por sentado en cada llamada).
    let resp = entorno
        .cliente
        .put(format!("{}/admin/users/{}", entorno.base, victima.user_id))
        .bearer_auth(sesion_admin)
        .json(&json!({ "active": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["active"], true);
}
