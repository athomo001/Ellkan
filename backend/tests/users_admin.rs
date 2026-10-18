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

/// Regresión: un recurso 100% personal (`user_key`, nadie más tiene acceso)
/// no debe bloquear la purga — antes bloqueaba con sólo "no hay otro Owner",
/// sin importar si alguien más podía siquiera verlo, así que cualquier
/// usuario con un solo recurso propio en su vault quedaba imposible de
/// borrar. El recurso tiene que desaparecer junto con el usuario (huérfano),
/// no quedar dando vueltas con un owner que ya no existe.
#[tokio::test]
async fn recurso_100_por_ciento_personal_no_bloquea_la_purga() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    let owner = common::registrar(&entorno, "dueno-personal@test.ellkan").await;
    let sesion_owner = common::login(&entorno, &owner).await;

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
    assert_eq!(cuerpo["blocks_purge"], false, "un recurso sin nadie más con acceso no debe bloquear");
    assert!(cuerpo["blocked_resources"].as_array().unwrap().is_empty());

    let resp = entorno
        .cliente
        .post(format!("{}/admin/users/{}/purge", entorno.base, owner.user_id))
        .bearer_auth(sesion_admin)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);

    let existe_usuario: (bool,) = sqlx::query_as("select exists(select 1 from users where id = $1)")
        .bind(owner.user_id)
        .fetch_one(&entorno.pool)
        .await
        .unwrap();
    assert!(!existe_usuario.0);

    let existe_recurso: (bool,) = sqlx::query_as("select exists(select 1 from resources where id = $1)")
        .bind(resource_id)
        .fetch_one(&entorno.pool)
        .await
        .unwrap();
    assert!(!existe_recurso.0, "el recurso huérfano tiene que borrarse junto con el usuario");
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

/// Regresión H-32 (auditoría 2026-08-12): `purgar()` validaba con CAS
/// (`rows_affected() != 1`) la transferencia de *managers* de grupo, pero no
/// la de *owners* de recurso — sólo hacía un `SELECT` previo, sin revisar el
/// `UPDATE` posterior. Ventana real: purgas concurrentes donde alguien
/// transfiere ownership a un usuario que se está purgando en simultáneo — la
/// ventana exacta (la fila de `permissions` desaparece ENTRE el `SELECT` y
/// el `UPDATE` de la misma transacción) es angosta a propósito y no se puede
/// forzar de forma determinística desde un test de integración sin
/// instrumentar la transacción. Este test simula el mismo resultado final
/// de forma secuencial (el destinatario ya no tiene ninguna fila de
/// `permissions` para cuando se intenta transferirle el recurso) y confirma
/// que el comportamiento observable es el que importa: rechazo explícito
/// (409), nunca éxito silencioso sin transferencia real.
#[tokio::test]
async fn purgar_con_transferencia_a_un_destinatario_ya_purgado_falla_explicito() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin-h32@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    let owner = common::registrar(&entorno, "owner-h32@test.ellkan").await;
    let sesion_owner = common::login(&entorno, &owner).await;
    let colaborador = common::registrar(&entorno, "colaborador-h32@test.ellkan").await;

    let par = KeypairAcuerdo::generar();
    let resp = entorno
        .cliente
        .post(format!("{}/admin/metadata-keys", entorno.base))
        .bearer_auth(sesion_admin)
        .json(&json!({
            "id": uuid::Uuid::now_v7(),
            "public_key_x25519_b64": B64.encode(par.publica().as_bytes()),
            "fingerprint": "fp-h32",
            "destinatarios": [],
        }))
        .send()
        .await
        .unwrap();
    let metadata_key: Value = resp.json().await.unwrap();
    let metadata_key_id = metadata_key["id"].as_str().unwrap();

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
            "level": "read",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);

    // El colaborador se purga primero (sin nada que lo bloquee: sólo tiene
    // `read`, no es owner de nada) — esto borra su fila de `permissions`
    // sobre el recurso, exactamente lo que la carrera real necesita.
    let resp = entorno
        .cliente
        .post(format!("{}/admin/users/{}/purge", entorno.base, colaborador.user_id))
        .bearer_auth(sesion_admin)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);

    // Ahora se purga al owner transfiriéndole el recurso al colaborador —
    // que ya no tiene ninguna fila de `permissions` sobre él. Antes de H-32
    // esto reportaba éxito (200) sin haber transferido nada de verdad.
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
    assert_eq!(resp.status(), 409, "transferir a un destinatario sin permiso real debe rechazarse, no reportar éxito");

    // Todo o nada: el owner original sigue existiendo, la purga no se aplicó a medias.
    let existe: (bool,) = sqlx::query_as("select exists(select 1 from users where id = $1)")
        .bind(owner.user_id)
        .fetch_one(&entorno.pool)
        .await
        .unwrap();
    assert!(existe.0, "una purga fallida no debe borrar nada (todo o nada)");
}

// ---------------------------------------------------------------------------
// F-40, transferencia de propiedad a grupos: el saliente es el único Owner de
// un recurso que sólo está compartido con un grupo (en lectura). Nadie del
// grupo tiene permiso directo, así que antes no había a quién transferirlo.
// ---------------------------------------------------------------------------

/// Escenario base: `owner` crea un recurso y lo comparte en lectura con el
/// grupo "Analistas" (un admin `jefe`, un miembro `analista`). Las
/// precondiciones de grupo se arman por SQL, igual que en `groups.rs`: lo
/// que se prueba acá es la transferencia, no el alta de miembros.
struct EscenarioGrupo {
    entorno: common::Entorno,
    sesion_admin: uuid::Uuid,
    owner: common::Usuario,
    jefe: common::Usuario,
    sesion_jefe: uuid::Uuid,
    analista: common::Usuario,
    group_id: uuid::Uuid,
    resource_id: uuid::Uuid,
}

async fn escenario_grupo(prefijo: &str) -> EscenarioGrupo {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, &format!("admin-{prefijo}@test.ellkan")).await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    let owner = common::registrar(&entorno, &format!("owner-{prefijo}@test.ellkan")).await;
    let sesion_owner = common::login(&entorno, &owner).await;
    let jefe = common::registrar(&entorno, &format!("jefe-{prefijo}@test.ellkan")).await;
    let sesion_jefe = common::login(&entorno, &jefe).await;
    let analista = common::registrar(&entorno, &format!("analista-{prefijo}@test.ellkan")).await;

    let par = KeypairAcuerdo::generar();
    let resp = entorno
        .cliente
        .post(format!("{}/admin/metadata-keys", entorno.base))
        .bearer_auth(sesion_admin)
        .json(&json!({
            "id": uuid::Uuid::now_v7(),
            "public_key_x25519_b64": B64.encode(par.publica().as_bytes()),
            "fingerprint": format!("fp-{prefijo}"),
            "destinatarios": [],
        }))
        .send()
        .await
        .unwrap();
    let metadata_key: Value = resp.json().await.unwrap();

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
            "metadata_key_id": metadata_key["id"].as_str().unwrap(),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);

    let group_id = uuid::Uuid::now_v7();
    let resp = entorno
        .cliente
        .post(format!("{}/groups", entorno.base))
        .bearer_auth(sesion_admin)
        .json(&json!({ "id": group_id, "name": format!("Analistas {prefijo}") }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);

    agregar_al_grupo(&entorno.pool, group_id, jefe.user_id, true, resource_id).await;
    agregar_al_grupo(&entorno.pool, group_id, analista.user_id, false, resource_id).await;
    sqlx::query(
        "insert into permissions (subject_type, subject_id, grantee_type, grantee_id, level)
         values ('resource', $1, 'group', $2, 'read')",
    )
    .bind(resource_id)
    .bind(group_id)
    .execute(&entorno.pool)
    .await
    .unwrap();

    EscenarioGrupo { entorno, sesion_admin, owner, jefe, sesion_jefe, analista, group_id, resource_id }
}

/// Membresía + el `secret_envelope` propio que el cliente le habría sellado
/// al miembro al compartir con el grupo.
async fn agregar_al_grupo(pool: &sqlx::PgPool, group_id: uuid::Uuid, user_id: uuid::Uuid, is_admin: bool, resource_id: uuid::Uuid) {
    sqlx::query("insert into group_members (group_id, user_id, is_admin) values ($1, $2, $3)")
        .bind(group_id)
        .bind(user_id)
        .bind(is_admin)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "insert into secret_envelopes (resource_id, user_id, sealed_dek, secret_ciphertext, secret_nonce)
         values ($1, $2, '\\x00', '\\x00', '\\x00')",
    )
    .bind(resource_id)
    .bind(user_id)
    .execute(pool)
    .await
    .unwrap();
}

async fn nivel_de(pool: &sqlx::PgPool, resource_id: uuid::Uuid, grantee_type: &str, grantee_id: uuid::Uuid) -> Option<String> {
    sqlx::query_as::<_, (String,)>(
        "select level from permissions where subject_type = 'resource' and subject_id = $1 and grantee_type = $2 and grantee_id = $3",
    )
    .bind(resource_id)
    .bind(grantee_type)
    .bind(grantee_id)
    .fetch_optional(pool)
    .await
    .unwrap()
    .map(|f| f.0)
}

async fn usuario_existe(pool: &sqlx::PgPool, user_id: uuid::Uuid) -> bool {
    sqlx::query_as::<_, (bool,)>("select exists(select 1 from users where id = $1)")
        .bind(user_id)
        .fetch_one(pool)
        .await
        .unwrap()
        .0
}

#[tokio::test]
async fn purgar_pasa_la_propiedad_a_los_admins_del_grupo() {
    let e = escenario_grupo("tg1").await;
    let base = &e.entorno.base;

    // El dry-run sugiere a los admins del grupo y los nombra.
    let resp = e
        .entorno
        .cliente
        .get(format!("{base}/admin/users/{}/purge/dry-run", e.owner.user_id))
        .bearer_auth(e.sesion_admin)
        .send()
        .await
        .unwrap();
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["blocks_purge"], true);
    let detalle = &cuerpo["blocked_resources_detail"][0];
    assert_eq!(detalle["resource_id"], json!(e.resource_id));
    assert_eq!(detalle["suggestion"], json!({ "type": "group_admins", "id": e.group_id }));
    let grupo = &detalle["groups"][0];
    assert_eq!(grupo["level"], "read");
    assert_eq!(grupo["members_with_access"], 2);
    assert_eq!(grupo["admins"].as_array().unwrap().len(), 1);
    assert_eq!(grupo["admins"][0]["user_id"], json!(e.jefe.user_id));

    let resp = e
        .entorno
        .cliente
        .post(format!("{base}/admin/users/{}/purge", e.owner.user_id))
        .bearer_auth(e.sesion_admin)
        .json(&json!({
            "transfer": { "owners": [{ "resource_id": e.resource_id, "to": { "type": "group_admins", "id": e.group_id } }] }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);

    let pool = &e.entorno.pool;
    assert!(!usuario_existe(pool, e.owner.user_id).await);
    assert_eq!(nivel_de(pool, e.resource_id, "user", e.jefe.user_id).await.as_deref(), Some("owner"));
    assert_eq!(nivel_de(pool, e.resource_id, "group", e.group_id).await.as_deref(), Some("read"), "el resto del grupo sigue leyendo");
    assert_eq!(nivel_de(pool, e.resource_id, "user", e.analista.user_id).await, None);

    // El jefe puede administrar el recurso: compartirlo exige ser Owner.
    let resp = e
        .entorno
        .cliente
        .post(format!("{base}/resources/{}/share", e.resource_id))
        .bearer_auth(e.sesion_jefe)
        .json(&json!({
            "recipient_user_id": e.analista.user_id,
            "sealed_dek_b64": "AAAA",
            "secret_ciphertext_b64": "AAAA",
            "secret_nonce_b64": "AAAA",
            "level": "update",
        }))
        .send()
        .await
        .unwrap();
    assert_ne!(resp.status(), 403, "el nuevo propietario tiene que poder administrar el recurso");

    // Queda auditado (el consumidor de auditoría escribe de forma asíncrona).
    let mut auditado = None;
    for _ in 0..50 {
        auditado = sqlx::query_as::<_, (String, String)>(
            "select metadata->>'to_type', metadata->>'from_user_id' from audit_log_entries
             where event_type = 'resource.ownership_transferred' and subject_id = $1",
        )
        .bind(e.resource_id)
        .fetch_optional(pool)
        .await
        .unwrap();
        if auditado.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(auditado, Some(("group_admins".to_string(), e.owner.user_id.to_string())));
}

#[tokio::test]
async fn purgar_pasa_la_propiedad_al_grupo_entero() {
    let e = escenario_grupo("tg2").await;
    let resp = e
        .entorno
        .cliente
        .post(format!("{}/admin/users/{}/purge", e.entorno.base, e.owner.user_id))
        .bearer_auth(e.sesion_admin)
        .json(&json!({
            "transfer": { "owners": [{ "resource_id": e.resource_id, "to": { "type": "group", "id": e.group_id } }] }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);
    assert_eq!(nivel_de(&e.entorno.pool, e.resource_id, "group", e.group_id).await.as_deref(), Some("owner"));
}

#[tokio::test]
async fn un_miembro_que_ve_por_grupo_puede_recibir_la_propiedad_como_usuario() {
    // Antes fallaba: el destino tenía que tener un permiso directo.
    let e = escenario_grupo("tg3").await;
    let resp = e
        .entorno
        .cliente
        .post(format!("{}/admin/users/{}/purge", e.entorno.base, e.owner.user_id))
        .bearer_auth(e.sesion_admin)
        .json(&json!({
            "transfer": { "owners": [{ "resource_id": e.resource_id, "new_owner_user_id": e.analista.user_id }] }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);
    assert_eq!(nivel_de(&e.entorno.pool, e.resource_id, "user", e.analista.user_id).await.as_deref(), Some("owner"));
}

#[tokio::test]
async fn destinos_invalidos_fallan_sin_tocar_nada() {
    let e = escenario_grupo("tg4").await;
    let base = &e.entorno.base;
    let ajeno = common::registrar(&e.entorno, "ajeno-tg4@test.ellkan").await;

    // Alguien sin envelope del recurso: no hay forma de sellárselo.
    let sin_acceso = json!({ "transfer": { "owners": [{ "resource_id": e.resource_id, "to": { "type": "user", "id": ajeno.user_id } }] } });
    // Un recurso que no bloquea: el admin no puede usar esto para repartir propiedad.
    let otro_recurso = json!({ "transfer": { "owners": [
        { "resource_id": e.resource_id, "to": { "type": "group_admins", "id": e.group_id } },
        { "resource_id": uuid::Uuid::now_v7(), "to": { "type": "user", "id": e.jefe.user_id } }
    ] } });
    // Los dos formatos a la vez: ambiguo.
    let ambiguo = json!({ "transfer": { "owners": [
        { "resource_id": e.resource_id, "new_owner_user_id": e.jefe.user_id, "to": { "type": "group", "id": e.group_id } }
    ] } });

    for (cuerpo, esperado) in [(sin_acceso, 409), (otro_recurso, 409), (ambiguo, 400)] {
        let resp = e
            .entorno
            .cliente
            .post(format!("{base}/admin/users/{}/purge", e.owner.user_id))
            .bearer_auth(e.sesion_admin)
            .json(&cuerpo)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), esperado, "{cuerpo}");
    }

    let pool = &e.entorno.pool;
    assert!(usuario_existe(pool, e.owner.user_id).await, "una transferencia rechazada no borra a nadie");
    assert_eq!(nivel_de(pool, e.resource_id, "user", e.jefe.user_id).await, None, "ni deja cambios a medias");
}

#[tokio::test]
async fn bloquear_con_transferencia_suma_propietarios_y_destraba_la_purga() {
    let e = escenario_grupo("tg5").await;
    let base = &e.entorno.base;
    let pool = &e.entorno.pool;

    let resp = e
        .entorno
        .cliente
        .put(format!("{base}/admin/users/{}", e.owner.user_id))
        .bearer_auth(e.sesion_admin)
        .json(&json!({
            "active": false,
            "transfer": { "owners": [{ "resource_id": e.resource_id, "to": { "type": "group_admins", "id": e.group_id } }] }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["active"], false);

    // Suma propietarios, no le quita nada al bloqueado (por si vuelve).
    assert_eq!(nivel_de(pool, e.resource_id, "user", e.jefe.user_id).await.as_deref(), Some("owner"));
    assert_eq!(nivel_de(pool, e.resource_id, "user", e.owner.user_id).await.as_deref(), Some("owner"));

    // Ya hay otro Owner: borrarlo después no pide otra transferencia.
    let resp = e
        .entorno
        .cliente
        .get(format!("{base}/admin/users/{}/purge/dry-run", e.owner.user_id))
        .bearer_auth(e.sesion_admin)
        .send()
        .await
        .unwrap();
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["blocks_purge"], false, "{cuerpo}");

    // Reactivar con transferencia no tiene sentido y se rechaza.
    let resp = e
        .entorno
        .cliente
        .put(format!("{base}/admin/users/{}", e.owner.user_id))
        .bearer_auth(e.sesion_admin)
        .json(&json!({
            "active": true,
            "transfer": { "owners": [{ "resource_id": e.resource_id, "to": { "type": "group", "id": e.group_id } }] }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn quitar_del_grupo_a_quien_ademas_es_owner_directo_no_le_borra_el_envelope() {
    // Bug previo: quitar a alguien de un grupo le borraba el envelope de
    // todo lo compartido con el grupo, aunque además tuviera acceso propio.
    let e = escenario_grupo("tg6").await;
    let base = &e.entorno.base;
    let pool = &e.entorno.pool;
    let jefe2 = common::registrar(&e.entorno, "jefe2-tg6@test.ellkan").await;
    agregar_al_grupo(pool, e.group_id, jefe2.user_id, true, e.resource_id).await;

    let resp = e
        .entorno
        .cliente
        .post(format!("{base}/admin/users/{}/purge", e.owner.user_id))
        .bearer_auth(e.sesion_admin)
        .json(&json!({
            "transfer": { "owners": [{ "resource_id": e.resource_id, "to": { "type": "group_admins", "id": e.group_id } }] }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);

    for miembro in [e.jefe.user_id, e.analista.user_id] {
        let resp = e
            .entorno
            .cliente
            .delete(format!("{base}/groups/{}/members/{miembro}", e.group_id))
            .bearer_auth(e.sesion_admin)
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success(), "{:?}", resp.text().await);
    }

    let tiene_envelope = |user_id: uuid::Uuid| {
        sqlx::query_as::<_, (bool,)>("select exists(select 1 from secret_envelopes where resource_id = $1 and user_id = $2)")
            .bind(e.resource_id)
            .bind(user_id)
            .fetch_one(pool)
    };
    assert!(tiene_envelope(e.jefe.user_id).await.unwrap().0, "el jefe sigue siendo Owner directo: conserva su envelope");
    assert!(!tiene_envelope(e.analista.user_id).await.unwrap().0, "el analista sólo lo veía por el grupo: se le revoca");
}
