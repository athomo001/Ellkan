// Autor: Athan Espinoza

//! F-13: criterios de aceptación literales — una acción administrativa
//! genera exactamente una entrada verificable por API; leer un secreto no
//! genera ninguna; un login fallido con email inexistente audita con
//! `actor_user_id = null`; la API nunca permite modificar/borrar una entrada
//! (ni siquiera a nivel de base, el trigger de la migración lo bloquea);
//! paginación por cursor; sólo `audit_log.read` (admin o rol `auditor`) lee
//! el log.

mod common;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ellkan_crypto::aead;
use ellkan_crypto::sellado;
use secrecy::SecretBox;
use serde_json::{json, Value};
use uuid::Uuid;

struct RecursoDePrueba {
    id: Uuid,
}

/// Recurso personal mínimo (`user_key`, sin compartir) — alcanza para
/// ejercitar creación/lectura de secreto.
async fn crear_recurso(entorno: &common::Entorno, sesion: Uuid, owner: &common::Usuario) -> RecursoDePrueba {
    let dek_bytes: [u8; 32] = ellkan_crypto::aleatoriedad::bytes_aleatorios();
    let dek_secreta = SecretBox::new(Box::new(dek_bytes));
    let resource_id = Uuid::now_v7();
    let mut aad = Vec::new();
    aad.extend_from_slice(resource_id.as_bytes());
    aad.extend_from_slice(owner.user_id.as_bytes());
    let metadata_env = aead::cifrar(&dek_secreta, b"{}", &aad).unwrap();
    let secreto_env = aead::cifrar(&dek_secreta, b"contenido-secreto", &aad).unwrap();
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
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    RecursoDePrueba { id: resource_id }
}

async fn crear_rol(entorno: &common::Entorno, sesion_admin: Uuid, name: &str) -> Value {
    let resp = entorno
        .cliente
        .post(format!("{}/admin/roles", entorno.base))
        .bearer_auth(sesion_admin)
        .json(&json!({ "name": name, "permissions": [] }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(status, 200, "crear rol debería funcionar para un admin, body: {cuerpo:?}");
    cuerpo
}

/// El consumidor de `DomainEvent::Auditoria` persiste en su propia tarea
/// tokio, desacoplado del request HTTP que lo dispara (F-13, mismo criterio
/// que la cola de emails de F-02) — se reintenta brevemente en vez de
/// asumir que ya está escrito apenas responde el endpoint que lo originó.
async fn esperar_items(
    entorno: &common::Entorno,
    sesion: Uuid,
    query: &str,
    minimo: usize,
) -> Vec<Value> {
    let mut ultimo = Vec::new();
    for _ in 0..30 {
        let resp = entorno
            .cliente
            .get(format!("{}/admin/audit-log?{query}", entorno.base))
            .bearer_auth(sesion)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let cuerpo: Value = resp.json().await.unwrap();
        let items = cuerpo["items"].as_array().cloned().unwrap_or_default();
        if items.len() >= minimo {
            return items;
        }
        ultimo = items;
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    ultimo
}

#[tokio::test]
async fn accion_administrativa_genera_exactamente_una_entrada() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin-audit-1@test.ellkan").await;
    let sesion_admin = common::login(&entorno, &admin).await;
    common::promover_admin(&entorno.pool, admin.user_id).await;

    let rol = crear_rol(&entorno, sesion_admin, "rol-de-prueba-audit-1").await;
    let role_id = rol["id"].as_str().unwrap();

    let items = esperar_items(
        &entorno,
        sesion_admin,
        &format!("event_type=role.created&actor_user_id={}", admin.user_id),
        1,
    )
    .await;

    assert_eq!(items.len(), 1, "debería haber exactamente una entrada de role.created: {items:?}");
    assert_eq!(items[0]["subject_type"], "role");
    assert_eq!(items[0]["subject_id"], role_id);
    assert_eq!(items[0]["actor_user_id"], admin.user_id.to_string());
}

#[tokio::test]
async fn leer_secreto_no_genera_ninguna_entrada() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin-audit-2@test.ellkan").await;
    let sesion_admin = common::login(&entorno, &admin).await;
    common::promover_admin(&entorno.pool, admin.user_id).await;

    let recurso = crear_recurso(&entorno, sesion_admin, &admin).await;

    // Espera a que la creación del recurso quede auditada (para no confundir
    // "todavía no llegó" con "leer no generó nada").
    let query_actor = format!("actor_user_id={}&limit=200", admin.user_id);
    let antes = esperar_items(&entorno, sesion_admin, &query_actor, 1).await;

    for _ in 0..3 {
        let resp = entorno
            .cliente
            .get(format!("{}/resources/{}/secret", entorno.base, recurso.id))
            .bearer_auth(sesion_admin)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    // Nada que esperar de verdad (no debería aparecer nada nuevo) — un
    // sleep corto alcanza para dejar pasar cualquier evento que, por un
    // bug, se hubiera emitido de más.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    let resp = entorno
        .cliente
        .get(format!("{}/admin/audit-log?{query_actor}", entorno.base))
        .bearer_auth(sesion_admin)
        .send()
        .await
        .unwrap();
    let cuerpo: Value = resp.json().await.unwrap();
    let despues = cuerpo["items"].as_array().cloned().unwrap_or_default();

    assert_eq!(
        antes.len(),
        despues.len(),
        "leer el secreto no debería agregar ninguna entrada nueva: antes={antes:?} despues={despues:?}"
    );
}

#[tokio::test]
async fn login_fallido_con_email_inexistente_audita_actor_null() {
    let entorno = common::levantar().await;
    // Necesita una sesión con `audit_log.read` para poder leer el resultado
    // — un admin de organización cualquiera alcanza.
    let admin = common::registrar(&entorno, "admin-audit-3@test.ellkan").await;
    let sesion_admin = common::login(&entorno, &admin).await;
    common::promover_admin(&entorno.pool, admin.user_id).await;

    let nonce: [u8; 32] = ellkan_crypto::aleatoriedad::bytes_aleatorios();
    let firma_falsa: [u8; 64] = [7u8; 64];
    let device_token_hash: [u8; 32] = ellkan_crypto::aleatoriedad::bytes_aleatorios();

    let resp = entorno
        .cliente
        .post(format!("{}/auth/verify", entorno.base))
        .json(&json!({
            "email": "no-existe-nunca@test.ellkan",
            "nonce_b64": B64.encode(nonce),
            "signature_b64": B64.encode(firma_falsa),
            "device_token_hash_b64": B64.encode(device_token_hash),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "un email inexistente debe fallar igual que credenciales inválidas");

    let items = esperar_items(&entorno, sesion_admin, "event_type=auth.login_failed", 1).await;
    assert_eq!(items.len(), 1);
    assert!(items[0]["actor_user_id"].is_null(), "actor_user_id debe ser null: {:?}", items[0]);
}

#[tokio::test]
async fn solo_admin_o_rol_auditor_puede_leer_el_audit_log() {
    let entorno = common::levantar().await;
    let bob = common::registrar(&entorno, "bob-audit@test.ellkan").await;
    let sesion_bob = common::login(&entorno, &bob).await;

    let resp = entorno
        .cliente
        .get(format!("{}/admin/audit-log", entorno.base))
        .bearer_auth(sesion_bob)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "un usuario regular no debería poder leer el audit log");

    sqlx::query("update users set role_id = (select id from roles where name = 'auditor') where id = $1")
        .bind(bob.user_id)
        .execute(&entorno.pool)
        .await
        .unwrap();

    let resp = entorno
        .cliente
        .get(format!("{}/admin/audit-log", entorno.base))
        .bearer_auth(sesion_bob)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "el rol auditor debería poder leer el audit log sin ser admin");
}

#[tokio::test]
async fn paginacion_por_cursor_recorre_todas_las_entradas_sin_repetir() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin-audit-4@test.ellkan").await;
    let sesion_admin = common::login(&entorno, &admin).await;
    common::promover_admin(&entorno.pool, admin.user_id).await;

    for i in 0..3 {
        crear_rol(&entorno, sesion_admin, &format!("rol-paginacion-{i}")).await;
    }

    let query_actor = format!("event_type=role.created&actor_user_id={}", admin.user_id);
    esperar_items(&entorno, sesion_admin, &query_actor, 3).await;

    let mut vistos = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut url = format!("{}/admin/audit-log?{query_actor}&limit=1", entorno.base);
        if let Some(c) = &cursor {
            url.push_str(&format!("&cursor={c}"));
        }
        let resp = entorno.cliente.get(&url).bearer_auth(sesion_admin).send().await.unwrap();
        assert_eq!(resp.status(), 200);
        let cuerpo: Value = resp.json().await.unwrap();
        let items = cuerpo["items"].as_array().unwrap();
        assert_eq!(items.len(), 1, "con limit=1 cada página trae exactamente un item");
        vistos.push(items[0]["id"].as_str().unwrap().to_string());

        match cuerpo["next_cursor"].as_str() {
            Some(c) => cursor = Some(c.to_string()),
            None => break,
        }
    }

    assert_eq!(vistos.len(), 3, "debería recorrer las 3 entradas sin repetir ni saltear: {vistos:?}");
    let unicos: std::collections::HashSet<_> = vistos.iter().collect();
    assert_eq!(unicos.len(), 3, "no debería haber ids repetidos entre páginas");
}

#[tokio::test]
async fn append_only_bloquea_update_y_delete_a_nivel_de_base() {
    let entorno = common::levantar().await;

    sqlx::query("insert into audit_log_entries (event_type) values ('auth.logout')")
        .execute(&entorno.pool)
        .await
        .unwrap();

    let resultado_update = sqlx::query("update audit_log_entries set event_type = 'auth.login_succeeded'")
        .execute(&entorno.pool)
        .await;
    assert!(resultado_update.is_err(), "un UPDATE sobre audit_log_entries debe fallar por el trigger");

    let resultado_delete = sqlx::query("delete from audit_log_entries").execute(&entorno.pool).await;
    assert!(resultado_delete.is_err(), "un DELETE sobre audit_log_entries debe fallar por el trigger");
}

#[tokio::test]
async fn export_soporta_ndjson_y_csv_y_rechaza_formato_desconocido() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin-audit-5@test.ellkan").await;
    let sesion_admin = common::login(&entorno, &admin).await;
    common::promover_admin(&entorno.pool, admin.user_id).await;

    crear_rol(&entorno, sesion_admin, "rol-export").await;
    esperar_items(
        &entorno,
        sesion_admin,
        &format!("event_type=role.created&actor_user_id={}", admin.user_id),
        1,
    )
    .await;

    let resp = entorno
        .cliente
        .get(format!("{}/admin/audit-log/export?format=ndjson", entorno.base))
        .bearer_auth(sesion_admin)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.headers().get("content-type").unwrap().to_str().unwrap().contains("ndjson"));
    let cuerpo = resp.text().await.unwrap();
    let primera_linea = cuerpo.lines().next().expect("al menos una línea NDJSON");
    let _: Value = serde_json::from_str(primera_linea).expect("cada línea es JSON válido");

    let resp = entorno
        .cliente
        .get(format!("{}/admin/audit-log/export?format=csv", entorno.base))
        .bearer_auth(sesion_admin)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.headers().get("content-type").unwrap().to_str().unwrap().contains("csv"));
    let cuerpo = resp.text().await.unwrap();
    let mut lineas = cuerpo.lines();
    assert!(lineas.next().unwrap().starts_with("id,actor_user_id,event_type"));
    assert!(lineas.next().is_some(), "debería haber al menos una fila de datos");

    let resp = entorno
        .cliente
        .get(format!("{}/admin/audit-log/export?format=xml", entorno.base))
        .bearer_auth(sesion_admin)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "un formato desconocido debe rechazarse explícitamente");
}

#[tokio::test]
async fn filtro_event_type_desconocido_falla_explicito() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin-audit-6@test.ellkan").await;
    let sesion_admin = common::login(&entorno, &admin).await;
    common::promover_admin(&entorno.pool, admin.user_id).await;

    let resp = entorno
        .cliente
        .get(format!("{}/admin/audit-log?event_type=no-existe", entorno.base))
        .bearer_auth(sesion_admin)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}
