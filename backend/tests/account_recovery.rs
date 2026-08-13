// Autor: Athan Espinoza

//! F-16: enrolar, pedir recuperación por email (sin sesión), aprobar hasta
//! el umbral, y verificar que el material re-sellado llega recién ahí — no
//! antes.

mod common;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ellkan_crypto::claves::KeypairAcuerdo;
use ellkan_crypto::clave_privada;
use ellkan_crypto::sellado;
use ellkan_crypto::secretos::PassphraseSecreta;
use secrecy::SecretBox;
use serde_json::{json, Value};
use uuid::Uuid;

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

/// Regresión de seguridad (auditoría 2026-08-12, H-27): `POST
/// /account-recovery/requests` es sin sesión (sólo email) — sin este
/// constraint, un atacante podía invocarlo repetidamente contra el email de
/// una víctima, insertando una fila `pending` nueva cada vez y disparando
/// una notificación real a los admins en cada una (mail-bombing).
#[tokio::test]
async fn segunda_solicitud_pendiente_para_el_mismo_escrow_es_rechazada() {
    let entorno = common::levantar().await;

    let victima = common::registrar(&entorno, "victima-dup@test.ellkan").await;
    let sesion_victima = common::login(&entorno, &victima).await;
    enrolar(&entorno, sesion_victima).await;

    let pedir = || {
        let entorno = &entorno;
        let email = victima.email.clone();
        async move {
            let efimera = KeypairAcuerdo::generar();
            entorno
                .cliente
                .post(format!("{}/account-recovery/requests", entorno.base))
                .json(&json!({
                    "email": email,
                    "requester_public_key_x25519_b64": B64.encode(efimera.publica().as_bytes()),
                }))
                .send()
                .await
                .unwrap()
        }
    };

    let resp = pedir().await;
    assert_eq!(resp.status(), 200, "la primera solicitud debería aceptarse");

    let resp = pedir().await;
    assert_eq!(resp.status(), 409, "una segunda solicitud mientras la primera sigue pendiente debería rechazarse");

    let count: (i64,) = sqlx::query_as(
        "select count(*) from account_recovery_requests r
         join account_recovery_escrow e on e.id = r.escrow_id
         where e.user_id = $1 and r.status = 'pending'",
    )
    .bind(victima.user_id)
    .fetch_one(&entorno.pool)
    .await
    .unwrap();
    assert_eq!(count.0, 1, "no debería haber quedado una segunda fila pending");
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

    // El cliente ya desselló `abierto` con su clave efímera arriba — ahora
    // fija una passphrase nueva y re-sella ese material antes de completar,
    // mismo flujo que `/me/change-passphrase` (tests/perfil.rs).
    let nueva_passphrase: PassphraseSecreta = SecretBox::new(Box::new("otra-passphrase-nueva-bien-larga".to_string()));
    let nueva_salt: [u8; 16] = ellkan_crypto::aleatoriedad::bytes_aleatorios();
    let nuevo_blob =
        clave_privada::cifrar_clave_privada(&nueva_passphrase, nueva_salt, &abierto, victima.email.as_bytes()).unwrap();

    let resp = entorno
        .cliente
        .post(format!("{}/account-recovery/requests/{request_id}/complete", entorno.base))
        .json(&json!({
            "encrypted_private_key_blob_b64": B64.encode(&nuevo_blob.envoltura.ciphertext),
            "private_key_nonce_b64": B64.encode(nuevo_blob.envoltura.nonce),
            "kdf_salt_b64": B64.encode(nuevo_blob.salt),
        }))
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

    // La sesión vieja de la víctima quedó invalidada (rotación de
    // `security_stamp` dentro de `CambiarPassphraseService::actualizar`).
    let resp =
        entorno.cliente.get(format!("{}/me", entorno.base)).bearer_auth(sesion_victima).send().await.unwrap();
    assert_eq!(resp.status(), 401, "completar la recuperación invalida cualquier sesión vieja de la víctima");

    // El blob nuevo quedó persistido de verdad.
    let fila: (Vec<u8>, Vec<u8>, Vec<u8>) = sqlx::query_as(
        "select encrypted_private_key_blob, private_key_nonce, kdf_salt from user_keys where user_id = $1",
    )
    .bind(victima.user_id)
    .fetch_one(&entorno.pool)
    .await
    .unwrap();
    assert_eq!(fila.0, nuevo_blob.envoltura.ciphertext);
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

#[tokio::test]
async fn admin_descubre_solicitudes_pendientes_por_el_listado() {
    let entorno = common::levantar().await;

    let victima = common::registrar(&entorno, "descubrible@test.ellkan").await;
    let sesion_victima = common::login(&entorno, &victima).await;
    let admin = common::registrar(&entorno, "admin-listado@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

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
        .get(format!("{}/admin/account-recovery/requests", entorno.base))
        .bearer_auth(sesion_admin)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cuerpo: Value = resp.json().await.unwrap();
    let solicitudes = cuerpo.as_array().unwrap();
    let encontrada = solicitudes.iter().find(|s| s["id"] == request_id).expect("la solicitud debe aparecer en el listado");
    assert_eq!(encontrada["target_email"], victima.email);
    assert_eq!(encontrada["status"], "pending");
    assert_eq!(encontrada["approvals_count"], 0);
    assert_eq!(encontrada["approval_threshold"], 1);

    // 2026-08-11: el extractor pasa de `AdminUser` a `AuthenticatedUser` —
    // la visibilidad ahora se filtra dentro del Service (admin de grupo vs.
    // de organización), así que un usuario sin ninguna autoridad ya no
    // recibe 403 acá, recibe 200 con una lista vacía (no ve nada, porque no
    // administra ningún grupo que comparta con el solicitante).
    let resp = entorno
        .cliente
        .get(format!("{}/admin/account-recovery/requests", entorno.base))
        .bearer_auth(sesion_victima)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cuerpo: Value = resp.json().await.unwrap();
    assert!(cuerpo.as_array().unwrap().is_empty(), "un usuario sin autoridad no debe ver ninguna solicitud");
}

/// 2026-08-11: delegación de autoridad a admin de grupo — mismo patrón que
/// `DELETE /resources/{id}`. Un admin del grupo AL QUE PERTENECE el
/// solicitante puede aprobar/rechazar/listar; un admin de un grupo NO
/// relacionado no puede (403); el evento de auditoría de esa acción trae
/// `metadata.authority` marcado como `"group_admin"`, distinguible de una
/// acción de admin de organización.
#[tokio::test]
async fn admin_de_grupo_del_solicitante_puede_gestionar_y_queda_bien_marcado_en_auditoria() {
    let entorno = common::levantar().await;

    let org_admin = common::registrar(&entorno, "org-admin-deleg@test.ellkan").await;
    common::promover_admin(&entorno.pool, org_admin.user_id).await;
    let sesion_org_admin = common::login(&entorno, &org_admin).await;

    let victima = common::registrar(&entorno, "victima-grupo@test.ellkan").await;
    let sesion_victima = common::login(&entorno, &victima).await;
    let admin_grupo = common::registrar(&entorno, "admin-grupo-deleg@test.ellkan").await;
    let sesion_admin_grupo = common::login(&entorno, &admin_grupo).await;
    let admin_otro_grupo = common::registrar(&entorno, "admin-otro-grupo-deleg@test.ellkan").await;
    let sesion_admin_otro_grupo = common::login(&entorno, &admin_otro_grupo).await;

    // Grupo del que la víctima es miembro (no admin) — `admin_grupo` lo administra.
    let grupo_id = Uuid::now_v7();
    let resp = entorno
        .cliente
        .post(format!("{}/groups", entorno.base))
        .bearer_auth(sesion_org_admin)
        .json(&json!({ "id": grupo_id, "name": "Grupo víctima" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    entorno
        .cliente
        .post(format!("{}/groups/{grupo_id}/members/{}", entorno.base, admin_grupo.user_id))
        .bearer_auth(sesion_org_admin)
        .json(&json!({ "is_admin": true, "envelopes": [] }))
        .send()
        .await
        .unwrap();
    entorno
        .cliente
        .post(format!("{}/groups/{grupo_id}/members/{}", entorno.base, victima.user_id))
        .bearer_auth(sesion_org_admin)
        .json(&json!({ "is_admin": false, "envelopes": [] }))
        .send()
        .await
        .unwrap();

    // Un segundo grupo, sin relación con la víctima — `admin_otro_grupo` lo administra.
    let otro_grupo_id = Uuid::now_v7();
    entorno
        .cliente
        .post(format!("{}/groups", entorno.base))
        .bearer_auth(sesion_org_admin)
        .json(&json!({ "id": otro_grupo_id, "name": "Grupo sin relación" }))
        .send()
        .await
        .unwrap();
    entorno
        .cliente
        .post(format!("{}/groups/{otro_grupo_id}/members/{}", entorno.base, admin_otro_grupo.user_id))
        .bearer_auth(sesion_org_admin)
        .json(&json!({ "is_admin": true, "envelopes": [] }))
        .send()
        .await
        .unwrap();

    enrolar(&entorno, sesion_victima).await;

    let crear_solicitud = || {
        let entorno = &entorno;
        let email = victima.email.clone();
        async move {
            let efimera = KeypairAcuerdo::generar();
            let resp = entorno
                .cliente
                .post(format!("{}/account-recovery/requests", entorno.base))
                .json(&json!({
                    "email": email,
                    "requester_public_key_x25519_b64": B64.encode(efimera.publica().as_bytes()),
                }))
                .send()
                .await
                .unwrap();
            let cuerpo: Value = resp.json().await.unwrap();
            cuerpo["id"].as_str().unwrap().to_string()
        }
    };

    // El admin de un grupo SIN relación no puede aprobar.
    let request_id = crear_solicitud().await;
    let resp = entorno
        .cliente
        .post(format!("{}/admin/account-recovery/requests/{request_id}/approve", entorno.base))
        .bearer_auth(sesion_admin_otro_grupo)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "admin de un grupo no relacionado con el solicitante no puede aprobar");

    // Tampoco lo ve en su listado.
    let resp = entorno
        .cliente
        .get(format!("{}/admin/account-recovery/requests", entorno.base))
        .bearer_auth(sesion_admin_otro_grupo)
        .send()
        .await
        .unwrap();
    let cuerpo: Value = resp.json().await.unwrap();
    assert!(cuerpo.as_array().unwrap().is_empty(), "admin de grupo no relacionado no debe ver la solicitud");

    // El admin del grupo de la víctima SÍ la ve y puede aprobarla.
    let resp = entorno
        .cliente
        .get(format!("{}/admin/account-recovery/requests", entorno.base))
        .bearer_auth(sesion_admin_grupo)
        .send()
        .await
        .unwrap();
    let cuerpo: Value = resp.json().await.unwrap();
    assert!(
        cuerpo.as_array().unwrap().iter().any(|s| s["id"] == request_id),
        "admin del grupo de la víctima debe ver la solicitud en su listado"
    );

    let resp = entorno
        .cliente
        .post(format!("{}/admin/account-recovery/requests/{request_id}/approve", entorno.base))
        .bearer_auth(sesion_admin_grupo)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "admin del grupo de la víctima debería poder aprobar");
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["status"], "approved");

    let fila: (String, Option<Uuid>) = sqlx::query_as(
        "select metadata->>'authority', (metadata->>'group_id')::uuid from audit_log_entries
         where event_type = 'account_recovery.approved' and subject_id = $1
         order by created_at desc limit 1",
    )
    .bind(uuid::Uuid::parse_str(&request_id).unwrap())
    .fetch_one(&entorno.pool)
    .await
    .unwrap();
    assert_eq!(fila.0, "group_admin", "la auditoría debe distinguir claramente una acción de admin de grupo");
    assert_eq!(fila.1, Some(grupo_id));

    // Rechazar sigue el mismo gate — otra solicitud, el admin no relacionado no puede rechazar.
    let request_id_2 = crear_solicitud().await;
    let resp = entorno
        .cliente
        .post(format!("{}/admin/account-recovery/requests/{request_id_2}/reject", entorno.base))
        .bearer_auth(sesion_admin_otro_grupo)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    let resp = entorno
        .cliente
        .post(format!("{}/admin/account-recovery/requests/{request_id_2}/reject", entorno.base))
        .bearer_auth(sesion_admin_grupo)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "admin del grupo de la víctima debería poder rechazar");
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["status"], "rejected");

    // Org admin puede aprobar/rechazar sin importar los grupos.
    let request_id_3 = crear_solicitud().await;
    let resp = entorno
        .cliente
        .post(format!("{}/admin/account-recovery/requests/{request_id_3}/approve", entorno.base))
        .bearer_auth(sesion_org_admin)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "admin de organización siempre puede aprobar, sin importar los grupos");
}

/// 2026-08-11: al crear una solicitud, los admins del grupo del solicitante
/// (no todos los admins de organización) reciben el email de aviso.
#[tokio::test]
async fn crear_solicitud_notifica_solo_a_admins_del_grupo_del_solicitante() {
    let entorno = common::levantar().await;

    let org_admin = common::registrar(&entorno, "org-admin-notif@test.ellkan").await;
    common::promover_admin(&entorno.pool, org_admin.user_id).await;
    let sesion_org_admin = common::login(&entorno, &org_admin).await;

    let victima = common::registrar(&entorno, "victima-notif@test.ellkan").await;
    let sesion_victima = common::login(&entorno, &victima).await;
    let admin_grupo = common::registrar(&entorno, "admin-grupo-notif@test.ellkan").await;

    let grupo_id = Uuid::now_v7();
    entorno
        .cliente
        .post(format!("{}/groups", entorno.base))
        .bearer_auth(sesion_org_admin)
        .json(&json!({ "id": grupo_id, "name": "Grupo notif" }))
        .send()
        .await
        .unwrap();
    entorno
        .cliente
        .post(format!("{}/groups/{grupo_id}/members/{}", entorno.base, admin_grupo.user_id))
        .bearer_auth(sesion_org_admin)
        .json(&json!({ "is_admin": true, "envelopes": [] }))
        .send()
        .await
        .unwrap();
    entorno
        .cliente
        .post(format!("{}/groups/{grupo_id}/members/{}", entorno.base, victima.user_id))
        .bearer_auth(sesion_org_admin)
        .json(&json!({ "is_admin": false, "envelopes": [] }))
        .send()
        .await
        .unwrap();

    enrolar(&entorno, sesion_victima).await;

    let efimera = KeypairAcuerdo::generar();
    entorno
        .cliente
        .post(format!("{}/account-recovery/requests", entorno.base))
        .json(&json!({
            "email": victima.email,
            "requester_public_key_x25519_b64": B64.encode(efimera.publica().as_bytes()),
        }))
        .send()
        .await
        .unwrap();

    let mut destinatarios = Vec::new();
    for _ in 0..20 {
        destinatarios = sqlx::query_scalar::<_, String>(
            "select recipient from outbound_emails where subject = 'Ellkan: solicitud de recuperación de cuenta pendiente'",
        )
        .fetch_all(&entorno.pool)
        .await
        .unwrap();
        if !destinatarios.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    assert_eq!(destinatarios, vec![admin_grupo.email.clone()], "sólo el admin del grupo de la víctima debe ser notificado");
}
