// Autor: Athan Espinoza

//! F-19: Directory Sync LDAP contra un OpenLDAP de prueba real
//! (`ELLKAN_TEST_LDAP_URL`, sembrado con `uid=carol` en
//! `ou=people,dc=ellkan-test,dc=example`) — TLS obligatorio (una corrida
//! contra `ldap://` sin StartTLS falla antes de intentar el bind), y un
//! dry-run real muestra el diff sin tocar `users`.

mod common;

use serde_json::{json, Value};

fn ldap_url() -> String {
    std::env::var("ELLKAN_TEST_LDAP_URL").unwrap_or_else(|_| "ldaps://localhost:6360".to_string())
}

async fn configurar(entorno: &common::Entorno, sesion_admin: uuid::Uuid, ldap_url: &str, require_starttls: bool) -> Value {
    let resp = entorno
        .cliente
        .put(format!("{}/admin/directory-sync/config", entorno.base))
        .bearer_auth(sesion_admin)
        .json(&json!({
            "ldap_url": ldap_url,
            "bind_dn": "cn=admin,dc=ellkan-test,dc=example",
            "bind_password": "admin_password",
            "require_starttls": require_starttls,
            "base_dn": "ou=people,dc=ellkan-test,dc=example",
            "attribute_mapping": { "external_id": "uid", "email": "mail", "display_name": "cn" },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);
    resp.json().await.unwrap()
}

#[tokio::test]
async fn mapear_userpassword_falla_al_guardar_la_config() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    let resp = entorno
        .cliente
        .put(format!("{}/admin/directory-sync/config", entorno.base))
        .bearer_auth(sesion_admin)
        .json(&json!({
            "ldap_url": "ldaps://localhost:6360",
            "bind_dn": "cn=admin,dc=ellkan-test,dc=example",
            "base_dn": "ou=people,dc=ellkan-test,dc=example",
            "attribute_mapping": { "external_id": "uid", "email": "userPassword" },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "mapear userPassword debe fallar aunque lo pida un admin");
}

#[tokio::test]
async fn correr_contra_ldap_sin_tls_falla_antes_de_intentar_el_bind() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    configurar(&entorno, sesion_admin, "ldap://localhost:3389", false).await;

    let resp = entorno
        .cliente
        .post(format!("{}/admin/directory-sync/dry-run", entorno.base))
        .bearer_auth(sesion_admin)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "ldap:// sin require_starttls debe rechazarse antes del bind");
}

#[tokio::test]
async fn dry_run_real_muestra_el_diff_sin_tocar_users() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    configurar(&entorno, sesion_admin, &ldap_url(), false).await;

    let resp = entorno
        .cliente
        .post(format!("{}/admin/directory-sync/dry-run", entorno.base))
        .bearer_auth(sesion_admin)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(status, 200, "{cuerpo:?}");
    assert_eq!(cuerpo["would_create"], json!(["carol"]), "carol (uid=carol) debería aparecer como alta nueva");

    let count: (i64,) = sqlx::query_as("select count(*) from users where external_id = 'carol'")
        .fetch_one(&entorno.pool)
        .await
        .unwrap();
    assert_eq!(count.0, 0, "el dry-run nunca debe crear filas reales");
}

#[tokio::test]
async fn apply_real_crea_el_usuario_y_repetir_no_duplica() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    configurar(&entorno, sesion_admin, &ldap_url(), false).await;

    let resp = entorno
        .cliente
        .post(format!("{}/admin/directory-sync/apply", entorno.base))
        .bearer_auth(sesion_admin)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);

    let fila: (String, bool) =
        sqlx::query_as("select email, active from users where external_id = 'carol'").fetch_one(&entorno.pool).await.unwrap();
    assert_eq!(fila.0, "carol@ellkan-test.example");
    assert!(fila.1);

    // Correr apply de nuevo no duplica a carol (ya gestionada, `unchanged`).
    let resp = entorno
        .cliente
        .post(format!("{}/admin/directory-sync/apply", entorno.base))
        .bearer_auth(sesion_admin)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let count: (i64,) =
        sqlx::query_as("select count(*) from users where external_id = 'carol'").fetch_one(&entorno.pool).await.unwrap();
    assert_eq!(count.0, 1);
}
