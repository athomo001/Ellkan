// Autor: Athan Espinoza

//! F-16: enrolar, pedir recuperación por email (sin sesión), aprobar hasta
//! el umbral, y verificar que el material re-sellado llega recién ahí — no
//! antes. QA-09: la clave organizacional la custodian los admins (el
//! re-sellado lo hace el navegador de un custodio) y la clave anterior,
//! custodiada por el servidor, se rota y se purga.

mod common;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ellkan_crypto::clave_privada;
use ellkan_crypto::claves::KeypairAcuerdo;
use ellkan_crypto::secretos::PassphraseSecreta;
use ellkan_crypto::sellado;
use secrecy::ExposeSecret;
use secrecy::SecretBox;
use serde_json::{Value, json};
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
            let fila: (String,) =
                sqlx::query_as("select body from outbound_emails where recipient = $1 and subject = $2 order by created_at desc limit 1")
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
    let filas: (i64,) = sqlx::query_as("select count(*) from account_recovery_requests")
        .fetch_one(&entorno.pool)
        .await
        .unwrap();
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

async fn org_public_key(entorno: &common::Entorno, sesion: Uuid) -> reqwest::Response {
    entorno
        .cliente
        .get(format!("{}/account-recovery/org-public-key", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap()
}

/// Enrola contra la clave vigente. Si la instancia todavía no tiene clave
/// organizacional, inserta una de cliente (como si un admin la hubiera
/// generado): los tests que no ejecutan el re-sellado no necesitan su
/// privada.
async fn enrolar_con_material(entorno: &common::Entorno, sesion: uuid::Uuid, material: [u8; 64]) -> [u8; 64] {
    let mut resp = org_public_key(entorno, sesion).await;
    if resp.status() == 404 {
        sqlx::query("insert into org_recovery_keys (public_key_x25519, custody) values ($1, 'client')")
            .bind(KeypairAcuerdo::generar().publica().as_bytes().to_vec())
            .execute(&entorno.pool)
            .await
            .unwrap();
        resp = org_public_key(entorno, sesion).await;
    }
    assert_eq!(resp.status(), 200);
    let cuerpo: Value = resp.json().await.unwrap();
    let org_publica_bytes = B64.decode(cuerpo["public_key_x25519_b64"].as_str().unwrap()).unwrap();
    let org_publica = x25519_dalek::PublicKey::from(<[u8; 32]>::try_from(org_publica_bytes.as_slice()).unwrap());
    let key_id = cuerpo["id"].as_i64().unwrap();

    let sellado_para_org = sellado::sellar_bytes(&org_publica, &material);
    let resp = enrolar_sellado(entorno, sesion, &sellado_para_org, key_id).await;
    assert_eq!(resp.status(), 200, "sesión válida debería poder enrolarse");
    material
}

async fn enrolar_sellado(entorno: &common::Entorno, sesion: Uuid, sellado_para_org: &[u8], key_id: i64) -> reqwest::Response {
    entorno
        .cliente
        .post(format!("{}/account-recovery/enroll", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({ "sealed_private_key_for_org_b64": B64.encode(sellado_para_org), "org_recovery_key_id": key_id }))
        .send()
        .await
        .unwrap()
}

/// QA-09: lo que hace el navegador de un admin al generar la clave
/// organizacional: el par nace acá y la privada viaja sólo sellada para
/// cada custodio.
async fn crear_clave_org(entorno: &common::Entorno, sesion: Uuid, custodios: &[&common::Usuario]) -> (reqwest::Response, KeypairAcuerdo) {
    let par = KeypairAcuerdo::generar();
    let privada = par.privada().to_bytes();
    let sobres: Vec<Value> = custodios
        .iter()
        .map(|c| {
            json!({
                "admin_id": c.user_id,
                "sealed_private_key_b64": B64.encode(sellado::sellar_bytes(c.x25519.publica(), privada.as_slice())),
            })
        })
        .collect();
    let resp = entorno
        .cliente
        .post(format!("{}/admin/account-recovery/org-keys", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({ "public_key_x25519_b64": B64.encode(par.publica().as_bytes()), "envelopes": sobres }))
        .send()
        .await
        .unwrap();
    (resp, par)
}

/// QA-09: lo que hace el navegador de un custodio con una solicitud que ya
/// juntó el umbral: abre su copia de la clave org, abre el escrow y lo
/// re-sella para la clave efímera del solicitante.
async fn ejecutar_como_custodio(
    entorno: &common::Entorno,
    custodio: &common::Usuario,
    sesion: Uuid,
    request_id: &str,
) -> reqwest::Response {
    let resp = entorno
        .cliente
        .get(format!("{}/admin/account-recovery/requests/{request_id}/custody-material", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    if resp.status() != 200 {
        return resp;
    }
    let m: Value = resp.json().await.unwrap();
    let campo = |k: &str| B64.decode(m[k].as_str().unwrap()).unwrap();
    let privada_org = sellado::abrir_bytes(custodio.x25519.privada(), &campo("envelope_b64")).unwrap();
    let privada_org = x25519_dalek::StaticSecret::from(<[u8; 32]>::try_from(privada_org.as_slice()).unwrap());
    let material = sellado::abrir_bytes(&privada_org, &campo("sealed_private_key_for_org_b64")).unwrap();
    let efimera = x25519_dalek::PublicKey::from(<[u8; 32]>::try_from(campo("requester_public_key_x25519_b64").as_slice()).unwrap());
    let resellado = sellado::sellar_bytes(&efimera, &material);
    entorno
        .cliente
        .post(format!("{}/admin/account-recovery/requests/{request_id}/execute", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({ "sealed_private_key_for_requester_b64": B64.encode(resellado) }))
        .send()
        .await
        .unwrap()
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

    // QA-09: la clave org la genera el admin y la custodia él.
    let (resp, _par) = crear_clave_org(&entorno, sesion_admin, &[&admin]).await;
    assert_eq!(resp.status(), 200);

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
    assert_eq!(cuerpo["status"], "awaiting_custodian", "el servidor no puede re-sellar: espera a un custodio");
    assert_eq!(cuerpo["sealed_private_key_for_requester_b64"], Value::Null);

    let resp = ejecutar_como_custodio(&entorno, &admin, sesion_admin, request_id).await;
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
    let nuevo_blob_sellado = clave_privada::cifrar_clave_privada(
        &nueva_passphrase,
        nueva_salt,
        ellkan_crypto::derivacion::ParametrosKdf::ACTUAL,
        &abierto,
        victima.email.as_bytes(),
    )
    .unwrap();
    let nuevo_blob = &nuevo_blob_sellado.blob;
    let (challenge, firma) = common::prueba_de_posesion(&entorno, &victima.email, &abierto[32..], &nuevo_blob_sellado).await;

    // QA-10: sin el token del solicitante (o con uno incorrecto) no se completa.
    let resp = entorno
        .cliente
        .post(format!("{}/account-recovery/requests/{request_id}/complete", entorno.base))
        .json(&json!({
            "requester_token_b64": B64.encode([0u8; 32]),
            "encrypted_private_key_blob_b64": B64.encode(&nuevo_blob.envoltura.ciphertext),
            "private_key_nonce_b64": B64.encode(nuevo_blob.envoltura.nonce),
            "kdf_salt_b64": B64.encode(nuevo_blob.salt),
            "kdf_params": ellkan_crypto::derivacion::ParametrosKdf::ACTUAL,
            "auth_key_b64": B64.encode(nuevo_blob_sellado.auth_key.expose_secret()),
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
            "kdf_params": ellkan_crypto::derivacion::ParametrosKdf::ACTUAL,
            "auth_key_b64": B64.encode(nuevo_blob_sellado.auth_key.expose_secret()),
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
    let resp = entorno
        .cliente
        .get(format!("{}/me", entorno.base))
        .bearer_auth(sesion_victima)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "completar la recuperación invalida cualquier sesión vieja de la víctima");

    // El blob nuevo quedó persistido de verdad.
    let fila: (Vec<u8>, Vec<u8>, Vec<u8>) =
        sqlx::query_as("select encrypted_private_key_blob, private_key_nonce, kdf_salt from user_keys where user_id = $1")
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
    let encontrada = solicitudes
        .iter()
        .find(|s| s["id"] == request_id)
        .expect("la solicitud debe aparecer en el listado");
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

    let (resp, _) = crear_clave_org(&entorno, sesion_org_admin, &[&org_admin]).await;
    assert_eq!(resp.status(), 200);
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

    // La auditoría la escribe un listener del canal de eventos, después de
    // la respuesta: se espera a que aparezca en vez de leerla una sola vez.
    let mut fila: Option<(String, Option<Uuid>)> = None;
    for _ in 0..50 {
        fila = sqlx::query_as(
            "select metadata->>'authority', (metadata->>'group_id')::uuid from audit_log_entries
             where event_type = 'account_recovery.approved' and subject_id = $1
             order by created_at desc limit 1",
        )
        .bind(uuid::Uuid::parse_str(&request_id).unwrap())
        .fetch_optional(&entorno.pool)
        .await
        .unwrap();
        if fila.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let fila = fila.expect("la aprobación debería quedar en la auditoría");
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
    assert_eq!(
        cuerpo["status"], "awaiting_custodian",
        "con un admin de organización se alcanza el umbral configurado; falta que un custodio re-selle"
    );
    // Un manager de grupo no es custodio: no ejecuta. El admin de organización sí.
    assert_eq!(ejecutar_como_custodio(&entorno, &admin_grupo, sesion_admin_grupo, &request_id).await.status(), 403);
    assert_eq!(ejecutar_como_custodio(&entorno, &org_admin, sesion_org_admin, &request_id).await.status(), 200);

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
    let avisos: (i64,) =
        sqlx::query_as("select count(*) from outbound_emails where subject = 'Ellkan: solicitud de recuperación de cuenta pendiente'")
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

    assert_eq!(
        destinatarios,
        vec![admin_grupo.email.clone()],
        "sólo el admin del grupo de la víctima debe ser notificado"
    );
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
    let fila: (bool,) = sqlx::query_as("select sealed_private_key_for_requester is not null from account_recovery_requests where id = $1")
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

async fn estado_custodia(entorno: &common::Entorno, sesion: Uuid) -> Value {
    let resp = entorno
        .cliente
        .get(format!("{}/admin/account-recovery/custody", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    resp.json().await.unwrap()
}

async fn agregar_custodio(entorno: &common::Entorno, sesion: Uuid, key_id: i64, custodio: &common::Usuario, privada_org: &[u8]) -> u16 {
    entorno
        .cliente
        .post(format!("{}/admin/account-recovery/org-keys/{key_id}/envelopes", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({
            "admin_id": custodio.user_id,
            "sealed_private_key_b64": B64.encode(sellado::sellar_bytes(custodio.x25519.publica(), privada_org)),
        }))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

async fn mi_estado(entorno: &common::Entorno, sesion: Uuid) -> Value {
    entorno
        .cliente
        .get(format!("{}/account-recovery/status", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// QA-09: la privada organizacional nace en el navegador de un admin y el
/// servidor sólo guarda copias selladas para cada custodio; sumar un
/// custodio lo hace otro custodio, nunca el servidor solo; el re-sellado
/// de una solicitud aprobada lo hace un custodio.
#[tokio::test]
async fn la_clave_org_la_custodian_los_admins_y_el_servidor_no_puede_abrirla() {
    let entorno = common::levantar().await;
    let admin1 = common::registrar(&entorno, "custodio1@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin1.user_id).await;
    let sesion_admin1 = common::login(&entorno, &admin1).await;
    let admin2 = common::registrar(&entorno, "custodio2@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin2.user_id).await;
    let sesion_admin2 = common::login(&entorno, &admin2).await;
    let victima = common::registrar(&entorno, "victima-custodia@test.ellkan").await;
    let sesion_victima = common::login(&entorno, &victima).await;

    // El servidor ya no genera la clave solo.
    assert_eq!(org_public_key(&entorno, sesion_victima).await.status(), 404);

    let (resp, _) = crear_clave_org(&entorno, sesion_victima, &[&victima]).await;
    assert_eq!(resp.status(), 403, "sólo un admin de organización crea la clave");
    let (resp, _) = crear_clave_org(&entorno, sesion_admin1, &[&admin2]).await;
    assert_eq!(resp.status(), 400, "la clave tiene que quedar sellada también para quien la crea");
    let (resp, _) = crear_clave_org(&entorno, sesion_admin1, &[&admin1, &victima]).await;
    assert_eq!(resp.status(), 400, "un custodio tiene que ser admin de organización");

    let (resp, par) = crear_clave_org(&entorno, sesion_admin1, &[&admin1]).await;
    assert_eq!(resp.status(), 200);
    let key_id = resp.json::<Value>().await.unwrap()["id"].as_i64().unwrap();
    let (cifrada,): (Option<Vec<u8>>,) = sqlx::query_as("select encrypted_private_key from org_recovery_keys where id = $1")
        .bind(key_id as i32)
        .fetch_one(&entorno.pool)
        .await
        .unwrap();
    assert!(cifrada.is_none(), "el servidor no guarda la privada");

    // admin2 todavía no es custodio: figura como pendiente y no puede sumar a nadie.
    let custodia = estado_custodia(&entorno, sesion_admin2).await;
    assert_eq!(custodia["current"]["custody"], "client");
    assert_eq!(custodia["my_envelope_b64"], Value::Null);
    let pendientes: Vec<&str> = custodia["pending_custodians"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["email"].as_str().unwrap())
        .collect();
    assert_eq!(pendientes, vec![admin2.email.as_str()]);
    let privada_org = par.privada().to_bytes();
    assert_eq!(agregar_custodio(&entorno, sesion_admin2, key_id, &admin2, privada_org.as_slice()).await, 403);

    // Lo suma un custodio, una sola vez, y sólo a admins.
    assert_eq!(agregar_custodio(&entorno, sesion_admin1, key_id, &victima, privada_org.as_slice()).await, 400);
    assert_eq!(agregar_custodio(&entorno, sesion_admin1, key_id, &admin2, privada_org.as_slice()).await, 204);
    assert_eq!(agregar_custodio(&entorno, sesion_admin1, key_id, &admin2, privada_org.as_slice()).await, 409);
    let custodia = estado_custodia(&entorno, sesion_admin2).await;
    assert!(custodia["my_envelope_b64"].is_string());
    assert!(custodia["pending_custodians"].as_array().unwrap().is_empty());

    // Recuperación: admin2 aprueba y re-sella.
    let original = enrolar_con_material(&entorno, sesion_victima, material_de(&victima)).await;
    let efimera = KeypairAcuerdo::generar();
    let (request_id, token) = pedir_y_confirmar(&entorno, &victima.email, &efimera).await;
    let cuerpo: Value = aprobar(&entorno, sesion_admin2, &request_id).await.json().await.unwrap();
    assert_eq!(cuerpo["status"], "awaiting_custodian");
    assert_eq!(aprobar(&entorno, sesion_admin2, &request_id).await.status(), 404, "ya juntó el umbral");
    let listado: Value = entorno
        .cliente
        .get(format!("{}/admin/account-recovery/requests", entorno.base))
        .bearer_auth(sesion_admin1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        listado
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["id"] == request_id.as_str() && s["status"] == "awaiting_custodian"),
        "la solicitud que espera custodio sigue en el listado"
    );

    let resp = entorno
        .cliente
        .get(format!("{}/admin/account-recovery/requests/{request_id}/custody-material", entorno.base))
        .bearer_auth(sesion_victima)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "sólo un admin pide el material");

    assert_eq!(ejecutar_como_custodio(&entorno, &admin2, sesion_admin2, &request_id).await.status(), 200);
    assert_eq!(
        ejecutar_como_custodio(&entorno, &admin2, sesion_admin2, &request_id).await.status(),
        404,
        "una solicitud ya re-sellada no se vuelve a entregar"
    );
    let cuerpo: Value = estado(&entorno, &request_id, Some(&token)).await.json().await.unwrap();
    assert_eq!(cuerpo["status"], "approved");
    let sellado_para_mi = B64.decode(cuerpo["sealed_private_key_for_requester_b64"].as_str().unwrap()).unwrap();
    assert_eq!(sellado::abrir_bytes(efimera.privada(), &sellado_para_mi).unwrap(), original);
}

/// Estado anterior a QA-09: la clave organizacional (id 1) la custodia el
/// servidor, cifrada con `ELLKAN_SECRETS_KEY`.
async fn insertar_clave_de_servidor(entorno: &common::Entorno) {
    let par = KeypairAcuerdo::generar();
    let secrets: ellkan_crypto::secretos::ClaveSecreta32 = SecretBox::new(Box::new(entorno.secrets_key));
    let envoltura = ellkan_crypto::aead::cifrar(&secrets, par.privada().to_bytes().as_slice(), b"org_recovery_key").unwrap();
    sqlx::query("insert into org_recovery_keys (id, public_key_x25519, encrypted_private_key, private_key_nonce) values (1, $1, $2, $3)")
        .bind(par.publica().as_bytes().to_vec())
        .bind(envoltura.ciphertext)
        .bind(envoltura.nonce.to_vec())
        .execute(&entorno.pool)
        .await
        .unwrap();
}

async fn clave_de_servidor_purgada(pool: &sqlx::PgPool) -> bool {
    let (purgada,): (bool,) =
        sqlx::query_as("select encrypted_private_key is null and purged_at is not null from org_recovery_keys where id = 1")
            .fetch_one(pool)
            .await
            .unwrap();
    purgada
}

/// QA-09, rotación: los escrows sellados contra la clave del servidor siguen
/// sirviendo (el servidor los re-sella como antes); al generar la clave de
/// cliente, cada usuario re-sella el suyo y, cuando no queda ninguno en la
/// clave del servidor, ésta se borra sola.
#[tokio::test]
async fn rotacion_desde_la_clave_del_servidor_y_purga_automatica() {
    let entorno = common::levantar().await;
    insertar_clave_de_servidor(&entorno).await;
    let admin = common::registrar(&entorno, "admin-rotacion@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;
    let victima1 = common::registrar(&entorno, "rotacion1@test.ellkan").await;
    let sesion1 = common::login(&entorno, &victima1).await;
    let victima2 = common::registrar(&entorno, "rotacion2@test.ellkan").await;
    let sesion2 = common::login(&entorno, &victima2).await;

    let original1 = enrolar_con_material(&entorno, sesion1, material_de(&victima1)).await;
    enrolar_con_material(&entorno, sesion2, material_de(&victima2)).await;
    let estado1 = mi_estado(&entorno, sesion1).await;
    assert_eq!(estado1["org_recovery_key_id"], 1);
    assert_eq!(estado1["current_org_recovery_key_id"], 1);

    // Escrow en la clave del servidor: se aprueba como antes, sin custodio.
    let efimera = KeypairAcuerdo::generar();
    let (request_id, _token) = pedir_y_confirmar(&entorno, &victima1.email, &efimera).await;
    let cuerpo: Value = aprobar(&entorno, sesion_admin, &request_id).await.json().await.unwrap();
    assert_eq!(cuerpo["status"], "approved");
    let sellado_para_mi = B64.decode(cuerpo["sealed_private_key_for_requester_b64"].as_str().unwrap()).unwrap();
    assert_eq!(sellado::abrir_bytes(efimera.privada(), &sellado_para_mi).unwrap(), original1);

    // Rotación.
    let estado = estado_custodia(&entorno, sesion_admin).await;
    assert_eq!(estado["current"]["custody"], "server");
    assert_eq!(estado["escrows_on_server_key"], 2);
    let (resp, _) = crear_clave_org(&entorno, sesion_admin, &[&admin]).await;
    assert_eq!(resp.status(), 200);
    let nueva_id = resp.json::<Value>().await.unwrap()["id"].as_i64().unwrap();
    assert_eq!(nueva_id, 2);
    let estado1 = mi_estado(&entorno, sesion1).await;
    assert_eq!(estado1["org_recovery_key_id"], 1);
    assert_eq!(estado1["current_org_recovery_key_id"], 2, "el cliente ve que tiene que re-sellar");

    // Sellar contra la clave vieja ya no vale.
    assert_eq!(enrolar_sellado(&entorno, sesion1, &[1u8; 112], 1).await.status(), 409);

    enrolar_con_material(&entorno, sesion1, material_de(&victima1)).await;
    assert!(!clave_de_servidor_purgada(&entorno.pool).await, "queda un escrow en la clave del servidor");
    enrolar_con_material(&entorno, sesion2, material_de(&victima2)).await;
    assert!(
        clave_de_servidor_purgada(&entorno.pool).await,
        "sin escrows en ella, la clave del servidor se borra"
    );
    assert_eq!(estado_custodia(&entorno, sesion_admin).await["escrows_on_server_key"], 0);
}

/// QA-09: el admin puede no esperar a que todos re-sellen; los escrows que
/// seguían en la clave del servidor se pierden (hay que volver a habilitar
/// la recuperación).
#[tokio::test]
async fn purgar_la_clave_del_servidor_a_mano() {
    let entorno = common::levantar().await;
    insertar_clave_de_servidor(&entorno).await;
    let admin = common::registrar(&entorno, "admin-purga@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;
    let victima = common::registrar(&entorno, "purga@test.ellkan").await;
    let sesion_victima = common::login(&entorno, &victima).await;
    enrolar_con_material(&entorno, sesion_victima, material_de(&victima)).await;

    let purgar = || async {
        entorno
            .cliente
            .delete(format!("{}/admin/account-recovery/server-key", entorno.base))
            .bearer_auth(sesion_admin)
            .send()
            .await
            .unwrap()
    };
    assert_eq!(purgar().await.status(), 409, "sin clave de cliente no se purga");

    let (resp, _) = crear_clave_org(&entorno, sesion_admin, &[&admin]).await;
    assert_eq!(resp.status(), 200);
    let resp = purgar().await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.json::<Value>().await.unwrap()["escrows_deleted"], 1);
    assert!(clave_de_servidor_purgada(&entorno.pool).await);
    assert_eq!(mi_estado(&entorno, sesion_victima).await["enrolled"], false);
}
