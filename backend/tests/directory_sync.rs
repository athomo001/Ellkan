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

/// 2026-08-11: config round-trip completo — no necesita LDAP real (corre
/// siempre en este sandbox). Cubre el bug real encontrado: la UI guardaba
/// `attribute_mapping: {}` fijo en cada save porque no tenía input para
/// eso, pisando lo configurado (el repository no hace `coalesce()` en esa
/// columna) — este test prueba el lado backend del arreglo: lo que se
/// manda en el `PUT` es exactamente lo que vuelve en el `GET` siguiente.
#[tokio::test]
async fn config_de_directory_sync_persiste_attribute_mapping_y_campos_de_grupos() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin-config-ds@test.ellkan").await;
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
            "attribute_mapping": { "external_id": "employeeID", "email": "mail", "display_name": "displayName" },
            "user_object_class": "user",
            "sync_groups": true,
            "group_membership_attribute": "memberOf",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);

    let resp = entorno
        .cliente
        .get(format!("{}/admin/directory-sync/config", entorno.base))
        .bearer_auth(sesion_admin)
        .send()
        .await
        .unwrap();
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["attribute_mapping"]["external_id"], "employeeID", "el mapeo configurado debe persistir, no pisarse con {{}}");
    assert_eq!(cuerpo["user_object_class"], "user", "objectClass configurable para Active Directory");
    assert_eq!(cuerpo["sync_groups"], true);
    assert_eq!(cuerpo["group_membership_attribute"], "memberOf");
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

/// `user_object_class` reemplaza el filtro base hardcodeado — con un
/// objectClass que no matchea a nadie, `would_create` queda vacío aunque
/// carol exista en el LDAP de prueba.
#[tokio::test]
async fn user_object_class_custom_cambia_el_filtro_base_efectivo() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin-objectclass@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    let resp = entorno
        .cliente
        .put(format!("{}/admin/directory-sync/config", entorno.base))
        .bearer_auth(sesion_admin)
        .json(&json!({
            "ldap_url": ldap_url(),
            "bind_dn": "cn=admin,dc=ellkan-test,dc=example",
            "bind_password": "admin_password",
            "require_starttls": false,
            "base_dn": "ou=people,dc=ellkan-test,dc=example",
            "attribute_mapping": { "external_id": "uid", "email": "mail", "display_name": "cn" },
            "user_object_class": "nonExistentObjectClass",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);

    let resp = entorno
        .cliente
        .post(format!("{}/admin/directory-sync/dry-run", entorno.base))
        .bearer_auth(sesion_admin)
        .send()
        .await
        .unwrap();
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["would_create"], json!([]), "un objectClass que no matchea a nadie no debe encontrar a carol");
}

/// F-19: sync de grupos vía un atributo multivaluado en la propia entrada
/// de usuario. Truco deliberado para no depender de datos de grupo del
/// fixture externo (`memberOf` real de `uid=carol` no está bajo control de
/// este repo, ver comentario del módulo): se apunta
/// `group_membership_attribute` a `mail`, un atributo que YA se sabe que
/// existe (mismo valor que usa `email`) — sirve igual para probar la
/// mecánica completa (lectura del atributo → resolución de nombre →
/// find-or-create de grupo raíz gestionado → alta de membresía →
/// reconciliación de baja al cambiar el atributo) sin inventar datos.
#[tokio::test]
async fn sync_groups_crea_grupo_gestionado_agrega_miembro_y_reconcilia_la_baja() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin-sync-groups@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    async fn configurar_con_grupo(entorno: &common::Entorno, sesion_admin: uuid::Uuid, atributo_grupo: &str) {
        let resp = entorno
            .cliente
            .put(format!("{}/admin/directory-sync/config", entorno.base))
            .bearer_auth(sesion_admin)
            .json(&json!({
                "ldap_url": ldap_url(),
                "bind_dn": "cn=admin,dc=ellkan-test,dc=example",
                "bind_password": "admin_password",
                "require_starttls": false,
                "base_dn": "ou=people,dc=ellkan-test,dc=example",
                "attribute_mapping": { "external_id": "uid", "email": "mail", "display_name": "cn" },
                "sync_groups": true,
                "group_membership_attribute": atributo_grupo,
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "{:?}", resp.text().await);
    }

    configurar_con_grupo(&entorno, sesion_admin, "mail").await;

    let resp = entorno
        .cliente
        .post(format!("{}/admin/directory-sync/apply", entorno.base))
        .bearer_auth(sesion_admin)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);

    let carol_id: uuid::Uuid =
        sqlx::query_scalar("select id from users where external_id = 'carol'").fetch_one(&entorno.pool).await.unwrap();

    let grupo: (uuid::Uuid, bool) =
        sqlx::query_as("select id, managed_by_directory_sync from groups where name = 'carol@ellkan-test.example'")
            .fetch_one(&entorno.pool)
            .await
            .unwrap();
    assert!(grupo.1, "el grupo creado por directory sync debe quedar marcado como gestionado");

    let es_miembro: (bool,) =
        sqlx::query_as("select exists(select 1 from group_members where group_id = $1 and user_id = $2)")
            .bind(grupo.0)
            .bind(carol_id)
            .fetch_one(&entorno.pool)
            .await
            .unwrap();
    assert!(es_miembro.0, "carol debería quedar como miembro del grupo gestionado recién creado");

    // Cambiar a otro atributo (cn) cambia el nombre de grupo "deseado" —
    // la próxima corrida debe sacar a carol del grupo viejo (ya no aparece
    // en el valor actual) y agregarla al nuevo.
    configurar_con_grupo(&entorno, sesion_admin, "cn").await;
    let resp = entorno
        .cliente
        .post(format!("{}/admin/directory-sync/apply", entorno.base))
        .bearer_auth(sesion_admin)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);

    let sigue_en_el_viejo: (bool,) =
        sqlx::query_as("select exists(select 1 from group_members where group_id = $1 and user_id = $2)")
            .bind(grupo.0)
            .bind(carol_id)
            .fetch_one(&entorno.pool)
            .await
            .unwrap();
    assert!(!sigue_en_el_viejo.0, "la reconciliación debe sacar a carol del grupo gestionado que ya no aplica");
}
