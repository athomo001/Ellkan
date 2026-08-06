// Autor: Athan Espinoza

//! F-18: alta idempotente por `externalId`, conflicto de email con cuenta
//! no-SCIM, y desactivación que invalida una sesión ya abierta de
//! inmediato.

mod common;

use serde_json::{json, Value};

async fn crear_token_scim(entorno: &common::Entorno, sesion_admin: uuid::Uuid) -> String {
    let resp = entorno
        .cliente
        .post(format!("{}/admin/scim-tokens", entorno.base))
        .bearer_auth(sesion_admin)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);
    let cuerpo: Value = resp.json().await.unwrap();
    cuerpo["token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn sin_token_scim_valido_falla() {
    let entorno = common::levantar().await;
    let resp = entorno
        .cliente
        .post(format!("{}/scim/v2/Users", entorno.base))
        .json(&json!({ "externalId": "x1", "userName": "x@test.ellkan" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn reintentar_el_mismo_external_id_no_crea_duplicado() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;
    let token = crear_token_scim(&entorno, sesion_admin).await;

    let payload = json!({
        "externalId": "okta-001",
        "userName": "dave@test.ellkan",
        "emails": [{ "value": "dave@test.ellkan" }],
    });

    let resp = entorno
        .cliente
        .post(format!("{}/scim/v2/Users", entorno.base))
        .bearer_auth(&token)
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "{:?}", resp.text().await);

    let resp = entorno
        .cliente
        .post(format!("{}/scim/v2/Users", entorno.base))
        .bearer_auth(&token)
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409, "reintentar el mismo externalId no debe crear un duplicado");

    let count: (i64,) = sqlx::query_as("select count(*) from users where external_id = 'okta-001'")
        .fetch_one(&entorno.pool)
        .await
        .unwrap();
    assert_eq!(count.0, 1);
}

#[tokio::test]
async fn conflicto_de_email_con_cuenta_no_scim_falla_sin_modificarla() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;
    let token = crear_token_scim(&entorno, sesion_admin).await;

    let manual = common::registrar(&entorno, "manual@test.ellkan").await;

    let resp = entorno
        .cliente
        .post(format!("{}/scim/v2/Users", entorno.base))
        .bearer_auth(&token)
        .json(&json!({
            "externalId": "okta-002",
            "userName": "manual@test.ellkan",
            "emails": [{ "value": "manual@test.ellkan" }],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409, "un email ya usado por una cuenta no-SCIM no debe fusionarse ni pisarse");

    let fila: (Option<String>,) = sqlx::query_as("select external_id from users where id = $1")
        .bind(manual.user_id)
        .fetch_one(&entorno.pool)
        .await
        .unwrap();
    assert_eq!(fila.0, None, "la cuenta manual no debe haberse tocado");
}

#[tokio::test]
async fn desactivar_via_scim_invalida_sesion_abierta_de_inmediato() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;
    let token = crear_token_scim(&entorno, sesion_admin).await;

    let resp = entorno
        .cliente
        .post(format!("{}/scim/v2/Users", entorno.base))
        .bearer_auth(&token)
        .json(&json!({
            "externalId": "okta-003",
            "userName": "erin@test.ellkan",
            "emails": [{ "value": "erin@test.ellkan" }],
        }))
        .send()
        .await
        .unwrap();
    let creado: Value = resp.json().await.unwrap();
    let user_id: uuid::Uuid = creado["id"].as_str().unwrap().parse().unwrap();

    // La cuenta SCIM-provisioned todavía no completó su propio enrolamiento
    // criptográfico — para simular "sesión ya abierta" se inserta una
    // sesión directo por SQL con el `security_stamp` vigente del usuario
    // (mismo invariante que produciría un login real).
    let stamp: (uuid::Uuid,) =
        sqlx::query_as("select security_stamp from users where id = $1").bind(user_id).fetch_one(&entorno.pool).await.unwrap();
    let session_id: (uuid::Uuid,) = sqlx::query_as(
        "insert into sessions (user_id, security_stamp, mfa_verified_at, expires_at) values ($1, $2, now(), now() + interval '1 hour') returning id",
    )
    .bind(user_id)
    .bind(stamp.0)
    .fetch_one(&entorno.pool)
    .await
    .unwrap();

    let resp = entorno
        .cliente
        .get(format!("{}/resources", entorno.base))
        .bearer_auth(session_id.0)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "la sesión insertada debe funcionar antes de desactivar");

    let resp = entorno
        .cliente
        .patch(format!("{}/scim/v2/Users/{user_id}", entorno.base))
        .bearer_auth(&token)
        .json(&json!({ "Operations": [{ "op": "replace", "value": { "active": false } }] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);

    let resp = entorno
        .cliente
        .get(format!("{}/resources", entorno.base))
        .bearer_auth(session_id.0)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "la sesión debe invalidarse de inmediato, no sólo al expirar");
}
