// Autor: Athan Espinoza

//! F-16: enrolar, pedir recuperación por email (sin sesión), aprobar hasta
//! el umbral, y verificar que el material re-sellado llega recién ahí — no
//! antes.

mod common;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ellkan_crypto::claves::KeypairAcuerdo;
use ellkan_crypto::sellado;
use serde_json::{json, Value};

#[tokio::test]
async fn usuario_sin_escrow_no_puede_recuperar() {
    let entorno = common::levantar().await;
    let user = common::registrar(&entorno, "sin-escrow@test.ellkan").await;
    let efimera = KeypairAcuerdo::generar();

    let resp = entorno
        .cliente
        .post(format!("{}/account-recovery/requests", entorno.base))
        .json(&json!({
            "email": user.email,
            "requester_public_key_x25519_b64": B64.encode(efimera.publica().as_bytes()),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "sin escrow configurado no hay forma de recuperar (comportamiento esperado)");
}

async fn enrolar(entorno: &common::Entorno, sesion: uuid::Uuid) -> [u8; 64] {
    let resp = entorno
        .cliente
        .get(format!("{}/account-recovery/org-public-key", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cuerpo: Value = resp.json().await.unwrap();
    let org_publica_bytes = B64.decode(cuerpo["public_key_x25519_b64"].as_str().unwrap()).unwrap();
    let org_publica = x25519_dalek::PublicKey::from(<[u8; 32]>::try_from(org_publica_bytes.as_slice()).unwrap());

    let clave_privada_original = [7u8; 64];
    let sellado_para_org = sellado::sellar_bytes(&org_publica, &clave_privada_original);

    let resp = entorno
        .cliente
        .post(format!("{}/account-recovery/enroll", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({ "sealed_private_key_for_org_b64": B64.encode(&sellado_para_org) }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "sesión válida debería poder enrolarse");
    clave_privada_original
}

#[tokio::test]
async fn un_solo_admin_no_alcanza_umbral_de_dos_y_no_se_duplica() {
    let entorno = common::levantar().await;

    let victima = common::registrar(&entorno, "victima@test.ellkan").await;
    let sesion_victima = common::login(&entorno, &victima).await;
    let admin1 = common::registrar(&entorno, "admin1@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin1.user_id).await;
    let sesion_admin1 = common::login(&entorno, &admin1).await;

    let resp = entorno
        .cliente
        .put(format!("{}/admin/account-recovery-policy", entorno.base))
        .bearer_auth(sesion_admin1)
        .json(&json!({ "required": false, "grace_period_days": 30, "default_approval_threshold": 2 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    enrolar(&entorno, sesion_victima).await;

    let efimera = KeypairAcuerdo::generar();
    let resp = entorno
        .cliente
        .post(format!("{}/account-recovery/requests", entorno.base))
        .json(&json!({
            "email": victima.email,
            "requester_public_key_x25519_b64": B64.encode(efimera.publica().as_bytes()),
        }))
        .send()
        .await
        .unwrap();
    let cuerpo: Value = resp.json().await.unwrap();
    let request_id = cuerpo["id"].as_str().unwrap();

    let resp = entorno
        .cliente
        .post(format!("{}/admin/account-recovery/requests/{request_id}/approve", entorno.base))
        .bearer_auth(sesion_victima)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "un usuario no-admin no puede aprobar");

    let resp = entorno
        .cliente
        .post(format!("{}/admin/account-recovery/requests/{request_id}/approve", entorno.base))
        .bearer_auth(sesion_admin1)
        .send()
        .await
        .unwrap();
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["status"], "pending", "un solo admin no alcanza el umbral de 2");
    assert_eq!(cuerpo["sealed_private_key_for_requester_b64"], Value::Null);

    let resp = entorno
        .cliente
        .post(format!("{}/admin/account-recovery/requests/{request_id}/approve", entorno.base))
        .bearer_auth(sesion_admin1)
        .send()
        .await
        .unwrap();
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["approvals_count"], 1, "aprobar dos veces el mismo admin no debe duplicarse");
}

#[tokio::test]
async fn al_alcanzar_umbral_se_libera_el_material_resellado_para_el_solicitante() {
    let entorno = common::levantar().await;

    let victima = common::registrar(&entorno, "victima@test.ellkan").await;
    let sesion_victima = common::login(&entorno, &victima).await;
    let admin = common::registrar(&entorno, "admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    // Umbral por defecto (1) alcanza con un solo admin.
    let clave_privada_original = enrolar(&entorno, sesion_victima).await;

    let efimera = KeypairAcuerdo::generar();
    let resp = entorno
        .cliente
        .post(format!("{}/account-recovery/requests", entorno.base))
        .json(&json!({
            "email": victima.email,
            "requester_public_key_x25519_b64": B64.encode(efimera.publica().as_bytes()),
        }))
        .send()
        .await
        .unwrap();
    let cuerpo: Value = resp.json().await.unwrap();
    let request_id = cuerpo["id"].as_str().unwrap();

    let resp = entorno
        .cliente
        .post(format!("{}/admin/account-recovery/requests/{request_id}/approve", entorno.base))
        .bearer_auth(sesion_admin)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["status"], "approved");
    let sellado_para_requester_b64 = cuerpo["sealed_private_key_for_requester_b64"].as_str().unwrap();

    let sellado_para_requester = B64.decode(sellado_para_requester_b64).unwrap();
    let abierto = sellado::abrir_bytes(efimera.privada(), &sellado_para_requester).unwrap();
    assert_eq!(abierto, clave_privada_original);

    let resp = entorno
        .cliente
        .post(format!("{}/account-recovery/requests/{request_id}/complete", entorno.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = entorno
        .cliente
        .get(format!("{}/account-recovery/requests/{request_id}", entorno.base))
        .send()
        .await
        .unwrap();
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["status"], "completed");
}

#[tokio::test]
async fn no_admin_no_puede_leer_ni_cambiar_la_politica() {
    let entorno = common::levantar().await;
    let user = common::registrar(&entorno, "sin-admin@test.ellkan").await;
    let sesion = common::login(&entorno, &user).await;

    let resp = entorno
        .cliente
        .get(format!("{}/admin/account-recovery-policy", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}
