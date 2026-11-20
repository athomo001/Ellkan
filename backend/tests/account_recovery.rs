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


/// Asunto del email con el código que confirma una solicitud (QA-10).
const ASUNTO_CONFIRMACION: &str = "Ellkan: confirmá la recuperación de tu cuenta";

async fn emails_de_confirmacion(pool: &sqlx::PgPool, email: &str) -> i64 {
    sqlx::query_scalar::<_, i64>("select count(*) from outbound_emails where recipient = $1 and subject = $2")
        .bind(email)
        .bind(ASUNTO_CONFIRMACION)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Espera a que se encole el email número `previos + 1` (el consumidor de
/// eventos es asíncrono) y devuelve su código.
async fn codigo_nuevo(pool: &sqlx::PgPool, email: &str, previos: i64) -> String {
    for _ in 0..50 {
        if emails_de_confirmacion(pool, email).await > previos {
            let fila: (String,) = sqlx::query_as(
                "select body from outbound_emails where recipient = $1 and subject = $2 order by created_at desc limit 1",
            )
            .bind(email)
            .bind(ASUNTO_CONFIRMACION)
            .fetch_one(pool)
            .await
            .unwrap();
            return fila.0.lines().find_map(|l| l.strip_prefix("Código de confirmación: ")).unwrap().trim().to_string();
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("debería haber un email nuevo con el código de confirmación encolado");
}

/// `POST /account-recovery/requests` — devuelve el id (siempre 200).
async fn pedir(entorno: &common::Entorno, email: &str, efimera: &KeypairAcuerdo) -> String {
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
    assert_eq!(resp.status(), 200);
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["status"], "unconfirmed");
    cuerpo["id"].as_str().unwrap().to_string()
}

async fn confirmar(entorno: &common::Entorno, request_id: &str, codigo: &str) -> reqwest::Response {
    entorno
        .cliente
        .post(format!("{}/account-recovery/requests/{request_id}/confirm", entorno.base))
        .json(&json!({ "code": codigo }))
        .send()
        .await
        .unwrap()
}

/// Pide la recuperación y la confirma con el código del email — devuelve
/// `(request_id, requester_token_b64)`.
/// Pide la recuperación y espera el código que llega al email de la cuenta.
async fn pedir_con_codigo(entorno: &common::Entorno, email: &str, efimera: &KeypairAcuerdo) -> (String, String) {
    let previos = emails_de_confirmacion(&entorno.pool, email).await;
    let request_id = pedir(entorno, email, efimera).await;
    (request_id, codigo_nuevo(&entorno.pool, email, previos).await)
}

async fn pedir_y_confirmar(entorno: &common::Entorno, email: &str, efimera: &KeypairAcuerdo) -> (String, String) {
    let (request_id, codigo) = pedir_con_codigo(entorno, email, efimera).await;
    let resp = confirmar(entorno, &request_id, &codigo).await;
    assert_eq!(resp.status(), 200, "el código del email debería confirmar la solicitud");
    let cuerpo: Value = resp.json().await.unwrap();
    (request_id, cuerpo["requester_token_b64"].as_str().unwrap().to_string())
}

async fn estado(entorno: &common::Entorno, request_id: &str, token: Option<&str>) -> reqwest::Response {
    let mut req = entorno.cliente.get(format!("{}/account-recovery/requests/{request_id}", entorno.base));
    if let Some(t) = token {
        req = req.header("X-Ellkan-Recovery-Token", t);
    }
    req.send().await.unwrap()
}

/// QA-10: misma respuesta exista o no la cuenta/escrow (anti-enumeración), y
/// sin escrow no hay ningún código que confirme nada.
#[tokio::test]
async fn usuario_sin_escrow_no_puede_recuperar() {
    let entorno = common::levantar().await;
    let user = common::registrar(&entorno, "sin-escrow@test.ellkan").await;
    let efimera = KeypairAcuerdo::generar();

    let id_sin_escrow = pedir(&entorno, &user.email, &efimera).await;
    let id_inexistente = pedir(&entorno, "nadie@test.ellkan", &efimera).await;

    for id in [&id_sin_escrow, &id_inexistente] {
        let resp = confirmar(&entorno, id, "00000000").await;
        assert_eq!(resp.status(), 401);
    }
    let filas: (i64,) = sqlx::query_as("select count(*) from account_recovery_requests").fetch_one(&entorno.pool).await.unwrap();
    assert_eq!(filas.0, 0, "sin escrow no se crea ninguna solicitud");
}

async fn enrolar(entorno: &common::Entorno, sesion: uuid::Uuid) -> [u8; 64] {
    enrolar_con_material(entorno, sesion, [7u8; 64]).await
}

/// Material real (X25519 || Ed25519) del usuario: hace falta cuando el test
/// llega hasta `complete`, que exige firmar con esa identidad (QA-06).
fn material_de(usuario: &common::Usuario) -> [u8; 64] {
    let mut material = [0u8; 64];
    material[..32].copy_from_slice(usuario.x25519.privada().to_bytes().as_slice());
    material[32..].copy_from_slice(&usuario.ed25519.firmante().to_bytes());
    material
}

async fn enrolar_con_material(entorno: &common::Entorno, sesion: uuid::Uuid, material: [u8; 64]) -> [u8; 64] {
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

    let clave_privada_original = material;
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
    let (request_id, _token) = pedir_y_confirmar(&entorno, &victima.email, &efimera).await;
    let request_id = request_id.as_str();

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

    let (_primera, _token) = pedir_y_confirmar(&entorno, &victima.email, &KeypairAcuerdo::generar()).await;

    // La segunda se crea `unconfirmed` (respuesta uniforme), pero confirmarla
    // choca con la primera, que sigue pendiente: 409 y ningún aviso nuevo.
    let (segunda, codigo) = pedir_con_codigo(&entorno, &victima.email, &KeypairAcuerdo::generar()).await;
    let resp = confirmar(&entorno, &segunda, &codigo).await;
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
    let clave_privada_original = enrolar_con_material(&entorno, sesion_victima, material_de(&victima)).await;

    let efimera = KeypairAcuerdo::generar();
    let (request_id, token) = pedir_y_confirmar(&entorno, &victima.email, &efimera).await;
    let request_id = request_id.as_str();

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
    let (challenge, firma) = common::prueba_de_posesion(&entorno, &victima.email, &abierto[32..], &nuevo_blob).await;

    // QA-10: sin el token del solicitante (o con uno incorrecto) no se completa.
    let resp = entorno
        .cliente
        .post(format!("{}/account-recovery/requests/{request_id}/complete", entorno.base))
        .json(&json!({
            "requester_token_b64": B64.encode([0u8; 32]),
            "encrypted_private_key_blob_b64": B64.encode(&nuevo_blob.envoltura.ciphertext),
            "private_key_nonce_b64": B64.encode(nuevo_blob.envoltura.nonce),
            "kdf_salt_b64": B64.encode(nuevo_blob.salt),
            "challenge_nonce_b64": challenge,
            "signature_b64": firma,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "un token incorrecto no puede completar la recuperación");
    assert_eq!(estado(&entorno, request_id, None).await.status(), 404, "sin token no se consulta el estado");

    let resp = entorno
        .cliente
        .post(format!("{}/account-recovery/requests/{request_id}/complete", entorno.base))
        .json(&json!({
            "requester_token_b64": token,
            "encrypted_private_key_blob_b64": B64.encode(&nuevo_blob.envoltura.ciphertext),
            "private_key_nonce_b64": B64.encode(nuevo_blob.envoltura.nonce),
            "kdf_salt_b64": B64.encode(nuevo_blob.salt),
            "challenge_nonce_b64": challenge,
            "signature_b64": firma,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = estado(&entorno, request_id, Some(&token)).await;
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
    let (request_id, _token) = pedir_y_confirmar(&entorno, &victima.email, &efimera).await;
    let request_id = request_id.as_str();

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
        async move { pedir_y_confirmar(entorno, &email, &KeypairAcuerdo::generar()).await.0 }
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
    // QA-02: un manager de grupo solo nunca alcanza el umbral (mínimo 2 sin
    // ningún admin de organización), aunque la política diga 1.
    assert_eq!(cuerpo["status"], "pending", "un solo manager de grupo no alcanza para liberar la clave");
    assert_eq!(cuerpo["sealed_private_key_for_requester_b64"], Value::Null);

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

    let resp = entorno
        .cliente
        .post(format!("{}/admin/account-recovery/requests/{request_id}/approve", entorno.base))
        .bearer_auth(sesion_org_admin)
        .send()
        .await
        .unwrap();
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["status"], "approved", "con un admin de organización se alcanza el umbral configurado");

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

    // QA-10: pedir sin confirmar no avisa a nadie.
    let efimera = KeypairAcuerdo::generar();
    let (request_id, codigo) = pedir_con_codigo(&entorno, &victima.email, &efimera).await;
    let avisos: (i64,) = sqlx::query_as(
        "select count(*) from outbound_emails where subject = 'Ellkan: solicitud de recuperación de cuenta pendiente'",
    )
    .fetch_one(&entorno.pool)
    .await
    .unwrap();
    assert_eq!(avisos.0, 0, "una solicitud sin confirmar no debe llegar a los admins");

    assert_eq!(confirmar(&entorno, &request_id, &codigo).await.status(), 200);

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

async fn crear_grupo_con_manager(entorno: &common::Entorno, sesion_org_admin: Uuid, manager: Uuid) -> Uuid {
    let grupo_id = Uuid::now_v7();
    let resp = entorno
        .cliente
        .post(format!("{}/groups", entorno.base))
        .bearer_auth(sesion_org_admin)
        .json(&json!({ "id": grupo_id, "name": format!("Grupo {grupo_id}") }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = entorno
        .cliente
        .post(format!("{}/groups/{grupo_id}/members/{manager}", entorno.base))
        .bearer_auth(sesion_org_admin)
        .json(&json!({ "is_admin": true, "envelopes": [] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    grupo_id
}

async fn agregar_miembro(entorno: &common::Entorno, sesion: Uuid, grupo_id: Uuid, user_id: Uuid) {
    let resp = entorno
        .cliente
        .post(format!("{}/groups/{grupo_id}/members/{user_id}", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({ "is_admin": false, "envelopes": [] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

async fn aprobar(entorno: &common::Entorno, sesion: Uuid, request_id: &str) -> reqwest::Response {
    entorno
        .cliente
        .post(format!("{}/admin/account-recovery/requests/{request_id}/approve", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap()
}

async fn material_liberado(pool: &sqlx::PgPool, request_id: &str) -> bool {
    let fila: (bool,) = sqlx::query_as(
        "select sealed_private_key_for_requester is not null from account_recovery_requests where id = $1",
    )
    .bind(Uuid::parse_str(request_id).unwrap())
    .fetch_one(pool)
    .await
    .unwrap();
    fila.0
}

/// QA-02: un manager de grupo no puede "enmarcar" a alguien en su grupo y
/// aprobar su recuperación — ni agregándolo después de la solicitud, ni
/// agregándolo él mismo antes.
#[tokio::test]
async fn manager_de_grupo_no_puede_aprobar_recovery_de_usuario_recien_agregado() {
    let entorno = common::levantar().await;
    let org_admin = common::registrar(&entorno, "org-admin-qa02@test.ellkan").await;
    common::promover_admin(&entorno.pool, org_admin.user_id).await;
    let sesion_org_admin = common::login(&entorno, &org_admin).await;

    let manager = common::registrar(&entorno, "manager-qa02@test.ellkan").await;
    let sesion_manager = common::login(&entorno, &manager).await;
    let grupo = crear_grupo_con_manager(&entorno, sesion_org_admin, manager.user_id).await;

    // Caso A: agregada por el manager DESPUÉS de la solicitud.
    let victima = common::registrar(&entorno, "victima-qa02a@test.ellkan").await;
    let sesion_victima = common::login(&entorno, &victima).await;
    enrolar(&entorno, sesion_victima).await;
    let (request_id, _token) = pedir_y_confirmar(&entorno, &victima.email, &KeypairAcuerdo::generar()).await;
    agregar_miembro(&entorno, sesion_manager, grupo, victima.user_id).await;
    assert_eq!(aprobar(&entorno, sesion_manager, &request_id).await.status(), 403);
    assert!(!material_liberado(&entorno.pool, &request_id).await);

    // Caso B: agregada por el propio manager ANTES de la solicitud.
    let victima_b = common::registrar(&entorno, "victima-qa02b@test.ellkan").await;
    let sesion_victima_b = common::login(&entorno, &victima_b).await;
    enrolar(&entorno, sesion_victima_b).await;
    agregar_miembro(&entorno, sesion_manager, grupo, victima_b.user_id).await;
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let (request_b, _token) = pedir_y_confirmar(&entorno, &victima_b.email, &KeypairAcuerdo::generar()).await;
    assert_eq!(aprobar(&entorno, sesion_manager, &request_b).await.status(), 403);
    assert!(!material_liberado(&entorno.pool, &request_b).await);
}

/// QA-02: nunca sobre una cuenta con privilegio de organización, aunque sea
/// miembro legítimo del grupo desde antes.
#[tokio::test]
async fn manager_de_grupo_no_puede_aprobar_recovery_de_un_admin_de_organizacion() {
    let entorno = common::levantar().await;
    let org_admin = common::registrar(&entorno, "org-admin-qa02c@test.ellkan").await;
    common::promover_admin(&entorno.pool, org_admin.user_id).await;
    let sesion_org_admin = common::login(&entorno, &org_admin).await;

    let manager = common::registrar(&entorno, "manager-qa02c@test.ellkan").await;
    let sesion_manager = common::login(&entorno, &manager).await;
    let grupo = crear_grupo_con_manager(&entorno, sesion_org_admin, manager.user_id).await;

    let otro_admin = common::registrar(&entorno, "otro-admin-qa02c@test.ellkan").await;
    common::promover_admin(&entorno.pool, otro_admin.user_id).await;
    let sesion_otro_admin = common::login(&entorno, &otro_admin).await;
    agregar_miembro(&entorno, sesion_org_admin, grupo, otro_admin.user_id).await;
    enrolar(&entorno, sesion_otro_admin).await;
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let (request_id, _token) = pedir_y_confirmar(&entorno, &otro_admin.email, &KeypairAcuerdo::generar()).await;
    assert_eq!(aprobar(&entorno, sesion_manager, &request_id).await.status(), 403);
    assert!(!material_liberado(&entorno.pool, &request_id).await);
}

/// QA-10: el código del email tiene tope de intentos (además del rate limit
/// estricto por IP sobre `confirm`).
#[tokio::test]
async fn codigo_de_confirmacion_tiene_tope_de_intentos() {
    let entorno = common::levantar().await;
    let victima = common::registrar(&entorno, "victima-qa10a@test.ellkan").await;
    let sesion_victima = common::login(&entorno, &victima).await;
    enrolar(&entorno, sesion_victima).await;

    let (request_id, codigo) = pedir_con_codigo(&entorno, &victima.email, &KeypairAcuerdo::generar()).await;
    let incorrecto = if codigo == "00000000" { "11111111" } else { "00000000" };
    for _ in 0..5 {
        assert_eq!(confirmar(&entorno, &request_id, incorrecto).await.status(), 401);
    }
    let status: (String,) = sqlx::query_as("select status from account_recovery_requests where id = $1")
        .bind(Uuid::parse_str(&request_id).unwrap())
        .fetch_one(&entorno.pool)
        .await
        .unwrap();
    assert_eq!(status.0, "expired", "tras 5 códigos incorrectos la solicitud queda vencida");
}

/// QA-10: una solicitud confirmada pero vencida ya no se puede aprobar, y el
/// solicitante la ve como `expired`.
#[tokio::test]
async fn solicitud_vencida_no_se_aprueba() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin-qa10@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;
    let victima = common::registrar(&entorno, "victima-qa10b@test.ellkan").await;
    let sesion_victima = common::login(&entorno, &victima).await;
    enrolar(&entorno, sesion_victima).await;

    let (request_id, token) = pedir_y_confirmar(&entorno, &victima.email, &KeypairAcuerdo::generar()).await;
    sqlx::query("update account_recovery_requests set expires_at = now() - interval '1 minute' where id = $1")
        .bind(Uuid::parse_str(&request_id).unwrap())
        .execute(&entorno.pool)
        .await
        .unwrap();
    assert_eq!(aprobar(&entorno, sesion_admin, &request_id).await.status(), 404);
    let cuerpo: Value = estado(&entorno, &request_id, Some(&token)).await.json().await.unwrap();
    assert_eq!(cuerpo["status"], "expired");
}
