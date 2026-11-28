// Autor: Athan Espinoza

//! spec/15 §3 (#52): verificación contra el directorio en el login y en la
//! sesión, contra el OpenLDAP de prueba (`levantar-fixtures.sh`, `uid=carol`).
//! Una cuenta que ya no está en el alcance no entra aunque el sync no haya
//! corrido; con el directorio caído, `grace` deja entrar sólo con una
//! verificación reciente y `deny` nunca.

mod common;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::Signer;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn ldap_url() -> String {
    std::env::var("ELLKAN_TEST_LDAP_URL").unwrap_or_else(|_| "ldaps://localhost:6360".to_string())
}

async fn configurar(entorno: &common::Entorno, sesion_admin: Uuid, url: &str, extra: Value) {
    let mut cuerpo = json!({
        "ldap_url": url,
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

/// Login desde un dispositivo ya conocido; devuelve el status de `verify`.
async fn intentar_login(entorno: &common::Entorno, usuario: &common::Usuario) -> u16 {
    let resp = entorno
        .cliente
        .post(format!("{}/auth/challenge", entorno.base))
        .json(&json!({ "email": usuario.email }))
        .send()
        .await
        .unwrap();
    let cuerpo: Value = resp.json().await.unwrap();
    let nonce = B64.decode(cuerpo["nonce_b64"].as_str().unwrap()).unwrap();
    let firma = usuario.ed25519.firmante().sign(&nonce);
    entorno
        .cliente
        .post(format!("{}/auth/verify", entorno.base))
        .json(&json!({
            "email": usuario.email,
            "nonce_b64": B64.encode(&nonce),
            "signature_b64": B64.encode(firma.to_bytes()),
            "device_token_hash_b64": B64.encode(Sha256::digest(usuario.device_token)),
        }))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

async fn vincular(entorno: &common::Entorno, user_id: Uuid, external_id: &str) {
    sqlx::query("update users set external_id = $2, managed_by = 'directory_sync', last_directory_check_at = null where id = $1")
        .bind(user_id)
        .bind(external_id)
        .execute(&entorno.pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn el_login_verifica_contra_el_directorio_y_aplica_la_baja() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let s_admin = common::login(&entorno, &admin).await;
    configurar(&entorno, s_admin, &ldap_url(), json!({})).await;

    // Cuenta enrolada atada a `uid=carol`, que existe en el directorio.
    let carol = common::registrar(&entorno, "carol-local@test.ellkan").await;
    let sesion = common::login(&entorno, &carol).await;
    vincular(&entorno, carol.user_id, "carol").await;
    assert_eq!(intentar_login(&entorno, &carol).await, 200);
    let verificada: Option<time::OffsetDateTime> = sqlx::query_scalar("select last_directory_check_at from users where id = $1")
        .bind(carol.user_id)
        .fetch_one(&entorno.pool)
        .await
        .unwrap();
    assert!(verificada.is_some(), "el login exitoso anota la verificación");

    // La misma cuenta, atada ahora a alguien que no está en el directorio
    // (borrado o fuera del alcance): no entra, queda desactivada y sus
    // sesiones abiertas mueren.
    vincular(&entorno, carol.user_id, "fantasma").await;
    assert_eq!(intentar_login(&entorno, &carol).await, 401);
    let activa: bool = sqlx::query_scalar("select active from users where id = $1")
        .bind(carol.user_id)
        .fetch_one(&entorno.pool)
        .await
        .unwrap();
    assert!(!activa, "la baja se aplica en el momento");
    let resp = entorno.cliente.get(format!("{}/me", entorno.base)).bearer_auth(sesion).send().await.unwrap();
    assert_eq!(resp.status(), 401, "la sesión que tenía abierta ya no sirve");

    let mut auditado = 0i64;
    for _ in 0..50 {
        auditado = sqlx::query_scalar(
            "select count(*) from audit_log_entries where event_type = 'user.deactivated' and subject_id = $1 and metadata->>'origen' = 'directory_check'",
        )
        .bind(carol.user_id)
        .fetch_one(&entorno.pool)
        .await
        .unwrap();
        if auditado > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(auditado, 1, "la baja queda en la auditoría con su origen");

    // Una cuenta local (no gestionada por el directorio) entra sin consulta.
    assert_eq!(intentar_login(&entorno, &admin).await, 200);
}

#[tokio::test]
async fn con_el_directorio_caido_grace_usa_la_ultima_verificacion_y_deny_rechaza() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let s_admin = common::login(&entorno, &admin).await;
    // Un puerto donde no escucha nadie: el directorio «no responde».
    configurar(&entorno, s_admin, "ldaps://127.0.0.1:1", json!({ "grace_seconds": 900 })).await;

    let u = common::registrar(&entorno, "u@test.ellkan").await;
    common::login(&entorno, &u).await;
    vincular(&entorno, u.user_id, "carol").await;

    // Verificado hace 5 min: entra.
    sqlx::query("update users set last_directory_check_at = now() - interval '5 minutes' where id = $1")
        .bind(u.user_id)
        .execute(&entorno.pool)
        .await
        .unwrap();
    assert_eq!(intentar_login(&entorno, &u).await, 200);

    // Verificado hace 1 h: no entra (y no se lo da de baja: no hay evidencia).
    sqlx::query("update users set last_directory_check_at = now() - interval '1 hour' where id = $1")
        .bind(u.user_id)
        .execute(&entorno.pool)
        .await
        .unwrap();
    assert_eq!(intentar_login(&entorno, &u).await, 401);
    let activa: bool = sqlx::query_scalar("select active from users where id = $1")
        .bind(u.user_id)
        .fetch_one(&entorno.pool)
        .await
        .unwrap();
    assert!(activa, "directorio caído no es una baja");

    // `deny`: ni con verificación reciente.
    configurar(&entorno, s_admin, "ldaps://127.0.0.1:1", json!({ "directory_unreachable_policy": "deny" })).await;
    sqlx::query("update users set last_directory_check_at = now() where id = $1")
        .bind(u.user_id)
        .execute(&entorno.pool)
        .await
        .unwrap();
    assert_eq!(intentar_login(&entorno, &u).await, 401);

    // Valores fuera de rango se rechazan.
    let resp = entorno
        .cliente
        .put(format!("{}/admin/directory-sync/config", entorno.base))
        .bearer_auth(s_admin)
        .json(&json!({ "ldap_url": "ldaps://127.0.0.1:1", "directory_unreachable_policy": "allow" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "no existe «permitir sin límite»");
}
