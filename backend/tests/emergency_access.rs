// Autor: Athan Espinoza

//! F-36: designar contacto, aceptar, denegar por política, aprobación
//! explícita del titular, y el job de timeout liberando por vencimiento sin
//! respuesta.

mod common;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};

#[tokio::test]
async fn flujo_designar_aceptar_solicitar_aprobar() {
    let entorno = common::levantar().await;

    let titular = common::registrar(&entorno, "titular@test.ellkan").await;
    let sesion_titular = common::login(&entorno, &titular).await;
    let contacto = common::registrar(&entorno, "contacto@test.ellkan").await;
    let sesion_contacto = common::login(&entorno, &contacto).await;

    let resp = entorno
        .cliente
        .post(format!("{}/me/emergency-access", entorno.base))
        .bearer_auth(sesion_titular)
        .json(&json!({
            "grantee_id": contacto.user_id,
            "access_level": "view",
            "sealed_material_b64": B64.encode(b"material-opaco-de-prueba"),
            "wait_time_days": 7,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cuerpo: Value = resp.json().await.unwrap();
    let id = cuerpo["id"].as_str().unwrap().to_string();
    assert_eq!(cuerpo["status"], "invited");

    // El contacto no puede pedir acceso antes de aceptar.
    let resp = entorno
        .cliente
        .post(format!("{}/me/emergency-access/{id}/request", entorno.base))
        .bearer_auth(sesion_contacto)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    let resp = entorno
        .cliente
        .post(format!("{}/me/emergency-access/{id}/accept", entorno.base))
        .bearer_auth(sesion_contacto)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = entorno
        .cliente
        .post(format!("{}/me/emergency-access/{id}/request", entorno.base))
        .bearer_auth(sesion_contacto)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Antes de aprobar, el material no se expone.
    let resp = entorno
        .cliente
        .get(format!("{}/me/emergency-access", entorno.base))
        .bearer_auth(sesion_contacto)
        .send()
        .await
        .unwrap();
    let lista: Value = resp.json().await.unwrap();
    let fila = lista.as_array().unwrap().iter().find(|f| f["id"] == id).unwrap();
    assert_eq!(fila["sealed_material_b64"], Value::Null, "sin aprobar, el material no debe exponerse");

    // El propio contacto no puede auto-aprobarse.
    let resp = entorno
        .cliente
        .post(format!("{}/me/emergency-access/{id}/approve", entorno.base))
        .bearer_auth(sesion_contacto)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    let resp = entorno
        .cliente
        .post(format!("{}/me/emergency-access/{id}/approve", entorno.base))
        .bearer_auth(sesion_titular)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = entorno
        .cliente
        .get(format!("{}/me/emergency-access", entorno.base))
        .bearer_auth(sesion_contacto)
        .send()
        .await
        .unwrap();
    let lista: Value = resp.json().await.unwrap();
    let fila = lista.as_array().unwrap().iter().find(|f| f["id"] == id).unwrap();
    assert_eq!(
        B64.decode(fila["sealed_material_b64"].as_str().unwrap()).unwrap(),
        b"material-opaco-de-prueba"
    );
}

#[tokio::test]
async fn deshabilitado_por_politica_rechaza_nueva_designacion() {
    let entorno = common::levantar().await;

    let admin = common::registrar(&entorno, "admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;
    let contacto = common::registrar(&entorno, "contacto@test.ellkan").await;

    let resp = entorno
        .cliente
        .put(format!("{}/admin/emergency-access-policy", entorno.base))
        .bearer_auth(sesion_admin)
        .json(&json!({ "enabled": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = entorno
        .cliente
        .post(format!("{}/me/emergency-access", entorno.base))
        .bearer_auth(sesion_admin)
        .json(&json!({
            "grantee_id": contacto.user_id,
            "access_level": "view",
            "sealed_material_b64": B64.encode(b"x"),
            "wait_time_days": 7,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "con la feature deshabilitada, designar debe fallar explícito");
}

#[tokio::test]
async fn el_titular_puede_revocar_y_desaparece_del_listado() {
    let entorno = common::levantar().await;

    let titular = common::registrar(&entorno, "titular@test.ellkan").await;
    let sesion_titular = common::login(&entorno, &titular).await;
    let contacto = common::registrar(&entorno, "contacto@test.ellkan").await;

    let resp = entorno
        .cliente
        .post(format!("{}/me/emergency-access", entorno.base))
        .bearer_auth(sesion_titular)
        .json(&json!({
            "grantee_id": contacto.user_id,
            "access_level": "takeover",
            "sealed_material_b64": B64.encode(b"x"),
            "wait_time_days": 7,
        }))
        .send()
        .await
        .unwrap();
    let cuerpo: Value = resp.json().await.unwrap();
    let id = cuerpo["id"].as_str().unwrap();

    let resp = entorno
        .cliente
        .delete(format!("{}/me/emergency-access/{id}", entorno.base))
        .bearer_auth(sesion_titular)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = entorno
        .cliente
        .get(format!("{}/me/emergency-access", entorno.base))
        .bearer_auth(sesion_titular)
        .send()
        .await
        .unwrap();
    let lista: Value = resp.json().await.unwrap();
    assert!(lista.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn solicitud_vencida_se_resuelve_por_timeout_via_repositorio() {
    use ellkan_backend::emergency_access::repository::{
        EmergencyAccessRepository, EmergencyAccessRequestRepository, PgEmergencyAccessRepository,
        PgEmergencyAccessRequestRepository,
    };

    let entorno = common::levantar().await;

    let titular = common::registrar(&entorno, "titular@test.ellkan").await;
    let sesion_titular = common::login(&entorno, &titular).await;
    let contacto = common::registrar(&entorno, "contacto@test.ellkan").await;
    let sesion_contacto = common::login(&entorno, &contacto).await;

    let resp = entorno
        .cliente
        .post(format!("{}/me/emergency-access", entorno.base))
        .bearer_auth(sesion_titular)
        .json(&json!({
            "grantee_id": contacto.user_id,
            "access_level": "view",
            "sealed_material_b64": B64.encode(b"x"),
            "wait_time_days": 1,
        }))
        .send()
        .await
        .unwrap();
    let cuerpo: Value = resp.json().await.unwrap();
    let id: uuid::Uuid = cuerpo["id"].as_str().unwrap().parse().unwrap();

    entorno
        .cliente
        .post(format!("{}/me/emergency-access/{id}/accept", entorno.base))
        .bearer_auth(sesion_contacto)
        .send()
        .await
        .unwrap();
    entorno
        .cliente
        .post(format!("{}/me/emergency-access/{id}/request", entorno.base))
        .bearer_auth(sesion_contacto)
        .send()
        .await
        .unwrap();

    // Simula que el plazo de 1 día ya venció, sin que el titular respondiera.
    sqlx::query("update emergency_access_requests set requested_at = now() - interval '2 days' where emergency_access_id = $1")
        .bind(id)
        .execute(&entorno.pool)
        .await
        .unwrap();

    let accesos = PgEmergencyAccessRepository { pool: entorno.pool.clone() };
    let requests = PgEmergencyAccessRequestRepository { pool: entorno.pool.clone() };

    let vencidas = requests.listar_vencidas().await.unwrap();
    assert_eq!(vencidas.len(), 1, "la solicitud vencida debe aparecer en el listado del job");
    assert_eq!(vencidas[0].1, titular.user_id);

    let resuelta = requests.resolver(vencidas[0].0.id, "granted_by_timeout").await.unwrap();
    assert!(resuelta);
    accesos.marcar_status(id, "confirmed").await.unwrap();

    let resp = entorno
        .cliente
        .get(format!("{}/me/emergency-access", entorno.base))
        .bearer_auth(sesion_contacto)
        .send()
        .await
        .unwrap();
    let lista: Value = resp.json().await.unwrap();
    let fila = lista.as_array().unwrap().iter().find(|f| f["id"] == id.to_string()).unwrap();
    assert_eq!(fila["status"], "confirmed");
    assert_eq!(
        B64.decode(fila["sealed_material_b64"].as_str().unwrap()).unwrap(),
        b"x",
        "tras el timeout, el contacto debe poder leer el material sin aprobación explícita"
    );
}
