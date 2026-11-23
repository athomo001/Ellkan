// Autor: Athan Espinoza

//! QA-38: la instancia nunca se queda sin administrador activo — ni por
//! SCIM ni por SQL directo (trigger `users_un_admin_activo`, migración 0060).

mod common;

use serde_json::{Value, json};
use uuid::Uuid;

async fn desactivar_por_scim(entorno: &common::Entorno, token: &str, user_id: Uuid) -> reqwest::Response {
    entorno
        .cliente
        .patch(format!("{}/scim/v2/Users/{user_id}", entorno.base))
        .bearer_auth(token)
        .json(&json!({ "Operations": [{ "op": "replace", "value": { "active": false } }] }))
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn scim_no_desactiva_al_ultimo_admin() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let bob = common::registrar(&entorno, "bob@test.ellkan").await;
    let sesion = common::login(&entorno, &admin).await;

    let resp = entorno
        .cliente
        .post(format!("{}/admin/scim-tokens", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    let token = resp.json::<Value>().await.unwrap()["token"].as_str().unwrap().to_string();
    // Las dos cuentas como si las hubiera creado el IdP.
    sqlx::query("update users set external_id = 'idp-' || id::text where id = any($1)")
        .bind(vec![admin.user_id, bob.user_id])
        .execute(&entorno.pool)
        .await
        .unwrap();

    let resp = desactivar_por_scim(&entorno, &token, admin.user_id).await;
    assert_eq!(resp.status(), 409);
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["error"]["code"], "LAST_ADMIN");
    let (activo,): (bool,) = sqlx::query_as("select active from users where id = $1")
        .bind(admin.user_id)
        .fetch_one(&entorno.pool)
        .await
        .unwrap();
    assert!(activo);

    // Un usuario común sí se desactiva.
    assert_eq!(desactivar_por_scim(&entorno, &token, bob.user_id).await.status(), 200);

    // Con otro admin activo, el primero ya se puede desactivar.
    let carla = common::registrar(&entorno, "carla@test.ellkan").await;
    common::promover_admin(&entorno.pool, carla.user_id).await;
    assert_eq!(desactivar_por_scim(&entorno, &token, admin.user_id).await.status(), 200);
}

#[tokio::test]
async fn sql_directo_tampoco_deja_la_instancia_sin_admin() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;

    for sentencia in [
        "update users set active = false where id = $1",
        "update users set deleted_at = now() where id = $1",
        "update users set role_id = (select id from roles where name = 'user') where id = $1",
    ] {
        let error = sqlx::query(sentencia).bind(admin.user_id).execute(&entorno.pool).await.unwrap_err();
        let codigo = error.as_database_error().and_then(|d| d.code()).map(|c| c.to_string());
        assert_eq!(codigo.as_deref(), Some("EK001"), "{sentencia}: {error}");
    }

    // Sacar a uno y promover a otro en la misma transacción sí vale: se
    // evalúa al confirmar.
    let bob = common::registrar(&entorno, "bob@test.ellkan").await;
    let mut tx = entorno.pool.begin().await.unwrap();
    sqlx::query("update users set active = false where id = $1")
        .bind(admin.user_id)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("update users set role_id = (select role_id from users where id = $2) where id = $1")
        .bind(bob.user_id)
        .bind(admin.user_id)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
}
