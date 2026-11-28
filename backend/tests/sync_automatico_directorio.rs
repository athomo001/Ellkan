// Autor: Athan Espinoza

//! spec/15 §2 (#53): sincronización automática con el directorio y freno de
//! bajas masivas (§2.5), contra el OpenLDAP de prueba (`levantar-fixtures.sh`,
//! sólo `uid=carol`).

mod common;

use serde_json::{Value, json};
use uuid::Uuid;

fn ldap_url() -> String {
    std::env::var("ELLKAN_TEST_LDAP_URL").unwrap_or_else(|_| "ldaps://localhost:6360".to_string())
}

async fn configurar(entorno: &common::Entorno, sesion_admin: Uuid, extra: Value) {
    let mut cuerpo = json!({
        "ldap_url": ldap_url(),
        "bind_dn": "cn=admin,dc=ellkan-test,dc=example",
        "bind_password": "admin_password",
        "base_dn": "ou=people,dc=ellkan-test,dc=example",
        "attribute_mapping": { "external_id": "uid", "email": "mail", "display_name": "cn" },
    });
    for (k, v) in extra.as_object().unwrap() {
        cuerpo[k] = v.clone();
    }
    let resp = entorno
        .cliente
        .put(format!("{}/admin/directory-sync/config", entorno.base))
        .bearer_auth(sesion_admin)
        .json(&cuerpo)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);
}

/// Cuentas «del directorio» que ya no están en el LDAP de prueba.
async fn sembrar_gestionadas(entorno: &common::Entorno, cuantas: usize) {
    for i in 0..cuantas {
        sqlx::query(
            "insert into users (email, display_name, external_id, managed_by, role_id, email_verified_at)
             values ($1, $1, $2, 'directory_sync', (select id from roles where name = 'user'), now())",
        )
        .bind(format!("ex{i}@test.ellkan"))
        .bind(format!("ex-{i}"))
        .execute(&entorno.pool)
        .await
        .unwrap();
    }
}

async fn activas(entorno: &common::Entorno) -> i64 {
    sqlx::query_scalar("select count(*) from users where external_id like 'ex-%' and active")
        .fetch_one(&entorno.pool)
        .await
        .unwrap()
}

async fn post(entorno: &common::Entorno, sesion: Uuid, ruta: &str) -> Value {
    let resp = entorno.cliente.post(format!("{}{ruta}", entorno.base)).bearer_auth(sesion).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    resp.json().await.unwrap()
}

#[tokio::test]
async fn bajas_masivas_abortan_la_corrida_hasta_que_un_admin_confirma() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let s_admin = common::login(&entorno, &admin).await;
    configurar(&entorno, s_admin, json!({})).await;

    // 6 bajas > tope automático (10 % de 6 → mínimo 5).
    sembrar_gestionadas(&entorno, 6).await;

    let dry = post(&entorno, s_admin, "/admin/directory-sync/dry-run").await;
    assert_eq!(dry["requires_confirmation"], true, "{dry}");
    assert_eq!(dry["would_deactivate"].as_array().unwrap().len(), 6);

    let r = post(&entorno, s_admin, "/admin/directory-sync/apply").await;
    assert_eq!(r["aborted"], true, "sin confirmar no se aplica nada: {r}");
    assert_eq!(activas(&entorno).await, 6);
    let carol: i64 = sqlx::query_scalar("select count(*) from users where external_id = 'carol'")
        .fetch_one(&entorno.pool)
        .await
        .unwrap();
    assert_eq!(carol, 0, "abortada entera: tampoco hay altas");

    let mut auditado = 0i64;
    for _ in 0..50 {
        auditado = sqlx::query_scalar("select count(*) from audit_log_entries where event_type = 'directory_sync.aborted_mass_deactivation'")
            .fetch_one(&entorno.pool)
            .await
            .unwrap();
        if auditado > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(auditado, 1);

    // Con un tope explícito más alto, pasa sin confirmar.
    configurar(&entorno, s_admin, json!({ "max_deactivations_per_run": 10 })).await;
    let r = post(&entorno, s_admin, "/admin/directory-sync/dry-run").await;
    assert_eq!(r["requires_confirmation"], false);

    // Volviendo al automático, el admin confirma y se aplica.
    configurar(&entorno, s_admin, json!({ "max_deactivations_per_run": 0 })).await;
    let r = post(&entorno, s_admin, "/admin/directory-sync/apply?confirm_mass_deactivation=true").await;
    assert_eq!(r["aborted"], false, "{r}");
    assert_eq!(activas(&entorno).await, 0);
    let gestionada: Option<String> = sqlx::query_scalar("select managed_by from users where external_id = 'carol'")
        .fetch_one(&entorno.pool)
        .await
        .unwrap();
    assert_eq!(gestionada.as_deref(), Some("directory_sync"), "lo que trae el sync queda gestionado (#52)");
}

#[tokio::test]
async fn la_sincronizacion_automatica_corre_sola() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let s_admin = common::login(&entorno, &admin).await;
    sembrar_gestionadas(&entorno, 1).await;
    configurar(&entorno, s_admin, json!({ "auto_sync_enabled": true, "poll_interval_seconds": 30 })).await;

    // El job mira cada 15 s; en ≤ 40 s tiene que haber corrido.
    let mut alta = 0i64;
    for _ in 0..80 {
        alta = sqlx::query_scalar("select count(*) from users where external_id = 'carol'")
            .fetch_one(&entorno.pool)
            .await
            .unwrap();
        if alta > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    assert_eq!(alta, 1, "la corrida automática dio de alta a carol");
    for _ in 0..20 {
        if activas(&entorno).await == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    assert_eq!(activas(&entorno).await, 0, "y desactivó la que ya no está (1 ≤ tope)");

    // Intervalo fuera de rango.
    let resp = entorno
        .cliente
        .put(format!("{}/admin/directory-sync/config", entorno.base))
        .bearer_auth(s_admin)
        .json(&json!({ "ldap_url": ldap_url(), "poll_interval_seconds": 5 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}
