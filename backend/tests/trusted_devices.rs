// Autor: Athan Espinoza

//! F-37: Trusted Device / Login with Device. El servidor nunca sella ni
//! desella nada — todos los blobs "sellados" acá son bytes aleatorios de
//! prueba, mismo criterio de fixtures que `groups.rs`/`metadata_keys.rs`.

mod common;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};
use uuid::Uuid;

/// Bytes de prueba simulando un blob ya sellado client-side — el servidor
/// nunca sella ni desella nada en F-37, así que cualquier bytes opacos
/// sirven para ejercitar el flujo (mismo criterio que `groups.rs`).
fn clave_publica_de_prueba() -> Vec<u8> {
    let bytes: [u8; 32] = ellkan_crypto::aleatoriedad::bytes_aleatorios();
    bytes.to_vec()
}

fn blob_sellado_de_prueba() -> Vec<u8> {
    let bytes: [u8; 64] = ellkan_crypto::aleatoriedad::bytes_aleatorios();
    bytes.to_vec()
}

#[tokio::test]
async fn marcar_dispositivo_propio_como_confiable() {
    let entorno = common::levantar().await;
    let usuario = common::registrar(&entorno, "trust-1@test.ellkan").await;
    let sesion = common::login(&entorno, &usuario).await;

    let device_public_key = clave_publica_de_prueba();
    let sealed = blob_sellado_de_prueba();
    let resp = entorno
        .cliente
        .post(format!("{}/me/devices/trust", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({
            "device_public_key_b64": B64.encode(&device_public_key),
            "sealed_user_private_key_b64": B64.encode(&sealed),
            "label": "mi laptop",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = entorno
        .cliente
        .get(format!("{}/me/devices", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let dispositivos: Value = resp.json().await.unwrap();
    assert_eq!(dispositivos.as_array().unwrap().len(), 1);
    assert_eq!(dispositivos[0]["label"], "mi laptop");
    assert!(dispositivos[0]["revoked_at"].is_null());
}

#[tokio::test]
async fn flujo_completo_peer_a_peer() {
    let entorno = common::levantar().await;
    let usuario = common::registrar(&entorno, "trust-2@test.ellkan").await;
    let sesion = common::login(&entorno, &usuario).await;

    // El dispositivo A ya es confiable.
    let device_a_public_key = clave_publica_de_prueba();
    entorno
        .cliente
        .post(format!("{}/me/devices/trust", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({
            "device_public_key_b64": B64.encode(&device_a_public_key),
            "sealed_user_private_key_b64": B64.encode(blob_sellado_de_prueba()),
            "label": "dispositivo A",
        }))
        .send()
        .await
        .unwrap();

    // El dispositivo B (nuevo, sin sesión) pide aprobación.
    let device_b_public_key = clave_publica_de_prueba();
    let resp = entorno
        .cliente
        .post(format!("{}/auth/device-approval/request", entorno.base))
        .json(&json!({ "email": usuario.email, "device_public_key_b64": B64.encode(&device_b_public_key) }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let solicitud: Value = resp.json().await.unwrap();
    let approval_id = solicitud["id"].as_str().unwrap();
    assert_eq!(solicitud["status"], "pending");
    let fingerprint_creada = solicitud["fingerprint"].as_str().unwrap().to_string();

    // B hace poll: sigue pendiente.
    let resp = entorno
        .cliente
        .get(format!("{}/auth/device-approval/{approval_id}", entorno.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let estado: Value = resp.json().await.unwrap();
    assert_eq!(estado["status"], "pending");
    assert_eq!(estado["sealed_user_private_key_b64"], Value::Null);

    // El dispositivo A (ya logueado, ya confiable) ve la solicitud pendiente...
    let resp = entorno
        .cliente
        .get(format!("{}/me/devices/pending-approvals", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let pendientes: Value = resp.json().await.unwrap();
    assert_eq!(pendientes.as_array().unwrap().len(), 1);
    assert_eq!(pendientes[0]["id"], approval_id);
    assert_eq!(pendientes[0]["fingerprint"], fingerprint_creada, "misma fingerprint en ambos lados a comparar");

    // ...y aprueba, sellando la clave del usuario para la pública de B.
    let sellado_para_b = blob_sellado_de_prueba();
    let resp = entorno
        .cliente
        .post(format!("{}/auth/device-approval/{approval_id}/approve", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({ "sealed_user_private_key_b64": B64.encode(&sellado_para_b) }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let texto = resp.text().await.unwrap();
    assert_eq!(status, 200, "approve debería devolver 200, body: {texto}");

    // B hace poll de nuevo: ahora aprobado, con sesión + clave sellada.
    let resp = entorno
        .cliente
        .get(format!("{}/auth/device-approval/{approval_id}", entorno.base))
        .send()
        .await
        .unwrap();
    let estado: Value = resp.json().await.unwrap();
    assert_eq!(estado["status"], "approved");
    assert!(estado["session_id"].is_string());
    let sellado_recibido = B64.decode(estado["sealed_user_private_key_b64"].as_str().unwrap()).unwrap();
    assert_eq!(sellado_recibido, sellado_para_b);

    // El dispositivo B, ahora aprobado, también quedó dado de alta como
    // confiable — la lista de dispositivos confiables del usuario tiene 2.
    let resp = entorno
        .cliente
        .get(format!("{}/me/devices", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    let dispositivos: Value = resp.json().await.unwrap();
    assert_eq!(dispositivos.as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn revocar_borra_la_clave_sellada() {
    let entorno = common::levantar().await;
    let usuario = common::registrar(&entorno, "trust-3@test.ellkan").await;
    let sesion = common::login(&entorno, &usuario).await;

    let resp = entorno
        .cliente
        .post(format!("{}/me/devices/trust", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({
            "device_public_key_b64": B64.encode(clave_publica_de_prueba()),
            "sealed_user_private_key_b64": B64.encode(blob_sellado_de_prueba()),
            "label": "a revocar",
        }))
        .send()
        .await
        .unwrap();
    let dispositivo: Value = resp.json().await.unwrap();
    let device_id = dispositivo["id"].as_str().unwrap();

    let resp = entorno
        .cliente
        .delete(format!("{}/me/devices/{device_id}", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let (revoked_at, sealed): (Option<time::OffsetDateTime>, Option<Vec<u8>>) =
        sqlx::query_as("select revoked_at, sealed_user_private_key from trusted_devices where id = $1")
            .bind(Uuid::parse_str(device_id).unwrap())
            .fetch_one(&entorno.pool)
            .await
            .unwrap();
    assert!(revoked_at.is_some());
    assert_eq!(sealed, None, "revocar debe borrar sealed_user_private_key, no sólo marcar la fila");
}

#[tokio::test]
async fn otro_usuario_no_puede_revocar_ni_aprobar_dispositivo_ajeno() {
    let entorno = common::levantar().await;
    let alice = common::registrar(&entorno, "trust-4-alice@test.ellkan").await;
    let bob = common::registrar(&entorno, "trust-4-bob@test.ellkan").await;
    let sesion_alice = common::login(&entorno, &alice).await;
    let sesion_bob = common::login(&entorno, &bob).await;

    let resp = entorno
        .cliente
        .post(format!("{}/me/devices/trust", entorno.base))
        .bearer_auth(sesion_alice)
        .json(&json!({
            "device_public_key_b64": B64.encode(clave_publica_de_prueba()),
            "sealed_user_private_key_b64": B64.encode(blob_sellado_de_prueba()),
            "label": "de alice",
        }))
        .send()
        .await
        .unwrap();
    let dispositivo: Value = resp.json().await.unwrap();
    let device_id = dispositivo["id"].as_str().unwrap();

    let resp = entorno
        .cliente
        .delete(format!("{}/me/devices/{device_id}", entorno.base))
        .bearer_auth(sesion_bob)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "bob no puede revocar un dispositivo de alice");

    // Bob pide aprobación para SU propia cuenta, y trata de que alice se la
    // apruebe usando el dispositivo de alice — actor_id != user_id de la
    // solicitud, debe fallar.
    let resp = entorno
        .cliente
        .post(format!("{}/auth/device-approval/request", entorno.base))
        .json(&json!({ "email": bob.email, "device_public_key_b64": B64.encode(clave_publica_de_prueba()) }))
        .send()
        .await
        .unwrap();
    let solicitud: Value = resp.json().await.unwrap();
    let approval_id = solicitud["id"].as_str().unwrap();

    let resp = entorno
        .cliente
        .post(format!("{}/auth/device-approval/{approval_id}/approve", entorno.base))
        .bearer_auth(sesion_alice)
        .json(&json!({ "sealed_user_private_key_b64": B64.encode(blob_sellado_de_prueba()) }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "alice no puede aprobar una solicitud de la cuenta de bob");
}

#[tokio::test]
async fn policy_sin_aprobacion_peer_rechaza_el_flujo_explicito() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "trust-5-admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;
    let usuario = common::registrar(&entorno, "trust-5@test.ellkan").await;
    common::login(&entorno, &usuario).await;

    let resp = entorno
        .cliente
        .put(format!("{}/admin/device-approval-policy", entorno.base))
        .bearer_auth(sesion_admin)
        .json(&json!({ "allow_peer_device_approval": false, "allow_admin_device_approval": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = entorno
        .cliente
        .post(format!("{}/auth/device-approval/request", entorno.base))
        .json(&json!({ "email": usuario.email, "device_public_key_b64": B64.encode(clave_publica_de_prueba()) }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "con la política apagada, ni siquiera se puede crear la solicitud");
}
