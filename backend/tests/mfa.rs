// Autor: Athan Espinoza

//! F-14/F-34: criterios de aceptación literales — con la política activa,
//! un usuario nuevo sin MFA configurado no puede completar el login hasta
//! configurar uno; un código MFA válido presentado junto con una sesión
//! parcial distinta a la que originó el desafío no le sirve a esa otra
//! sesión (el binding por hash es real, no un adorno); intentos repetidos
//! de código incorrecto activan el rate limit dedicado.

mod common;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::Signer;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

async fn activar_mfa_requerido(entorno: &common::Entorno, sesion_admin: Uuid) {
    let resp = entorno
        .cliente
        .put(format!("{}/admin/mfa-policy", entorno.base))
        .bearer_auth(sesion_admin)
        .json(&json!({ "require_mfa": true, "allowed_methods": ["totp"], "grace_period_days": 7 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "un admin debería poder activar require_mfa");
}

/// Igual que `common::login`, pero sin asumir que el resultado es
/// "completo" — completa F-02 (dispositivo) si hace falta y devuelve el
/// body crudo de la respuesta final (`/auth/verify` o `/auth/verify-device`).
async fn intentar_login(entorno: &common::Entorno, usuario: &common::Usuario) -> Value {
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
    let device_token_hash_b64 = B64.encode(Sha256::digest(usuario.device_token));

    let resp = entorno
        .cliente
        .post(format!("{}/auth/verify", entorno.base))
        .json(&json!({
            "email": usuario.email,
            "nonce_b64": B64.encode(&nonce),
            "signature_b64": B64.encode(firma.to_bytes()),
            "device_token_hash_b64": device_token_hash_b64,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cuerpo: Value = resp.json().await.unwrap();

    if cuerpo["estado"] != "pendiente_dispositivo" {
        return cuerpo;
    }

    let device_challenge_id = cuerpo["device_challenge_id"].as_str().unwrap();
    let codigo = codigo_de_verificacion_encolado(&entorno.pool, &usuario.email).await;

    let resp = entorno
        .cliente
        .post(format!("{}/auth/verify-device", entorno.base))
        .json(&json!({ "device_challenge_id": device_challenge_id, "code": codigo }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    resp.json().await.unwrap()
}

// F-24: filtra por `subject` — `registrar()` ahora también encola un email
// de verificación de cuenta para cualquier usuario no-bootstrap, así que
// puede haber más de una fila para el mismo `recipient` (ver el comentario
// equivalente en `common/mod.rs`).
async fn codigo_de_verificacion_encolado(pool: &sqlx::PgPool, email: &str) -> String {
    for _ in 0..20 {
        if let Ok(fila) = sqlx::query_as::<_, (String,)>(
            "select body from outbound_emails where recipient = $1 and subject = $2 order by created_at desc limit 1",
        )
        .bind(email)
        .bind("Ellkan: verificá este dispositivo nuevo")
        .fetch_one(pool)
        .await
        {
            return fila
                .0
                .lines()
                .find_map(|l| l.strip_prefix("Código de verificación: "))
                .unwrap()
                .trim()
                .to_string();
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("debería haber un email de verificación de dispositivo encolado");
}

fn generar_codigo_actual(secreto: &[u8]) -> u32 {
    let ahora = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
    ellkan_crypto::totp::codigo_totp(secreto, ahora)
}

async fn puede_operar(entorno: &common::Entorno, sesion: Uuid) -> bool {
    entorno
        .cliente
        .get(format!("{}/resources", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap()
        .status()
        == 200
}

#[tokio::test]
async fn sin_politica_activa_el_login_sigue_completo() {
    let entorno = common::levantar().await;
    let usuario = common::registrar(&entorno, "mfa-sin-politica@test.ellkan").await;
    let cuerpo = intentar_login(&entorno, &usuario).await;
    assert_eq!(cuerpo["estado"], "completo");
}

#[tokio::test]
async fn usuario_nuevo_sin_mfa_configurado_debe_configurar_antes_de_operar() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "mfa-admin-1@test.ellkan").await;
    let sesion_admin = common::login(&entorno, &admin).await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    activar_mfa_requerido(&entorno, sesion_admin).await;

    // Se registra DESPUÉS de que la política ya está activa — sin gracia.
    let usuario = common::registrar(&entorno, "mfa-nuevo@test.ellkan").await;
    let cuerpo = intentar_login(&entorno, &usuario).await;
    assert_eq!(cuerpo["estado"], "requiere_configurar_mfa");
    let sesion_parcial: Uuid = cuerpo["session_id"].as_str().unwrap().parse().unwrap();

    assert!(!puede_operar(&entorno, sesion_parcial).await, "una sesión parcial no debería poder operar");

    // Setup + confirm con el primer código válido completa esa misma sesión.
    let resp = entorno
        .cliente
        .post(format!("{}/me/mfa/totp/setup", entorno.base))
        .bearer_auth(sesion_parcial)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cuerpo: Value = resp.json().await.unwrap();
    let secreto = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, cuerpo["secret_base32"].as_str().unwrap())
        .unwrap();

    let resp = entorno
        .cliente
        .post(format!("{}/me/mfa/totp/confirm", entorno.base))
        .bearer_auth(sesion_parcial)
        .json(&json!({ "code": generar_codigo_actual(&secreto).to_string() }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "el primer código válido debería confirmar el setup");

    assert!(puede_operar(&entorno, sesion_parcial).await, "tras confirmar TOTP la sesión ya debería operar");
}

#[tokio::test]
async fn login_posterior_con_totp_ya_confirmado_queda_pendiente_de_verificar() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "mfa-admin-2@test.ellkan").await;
    let sesion_admin = common::login(&entorno, &admin).await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    activar_mfa_requerido(&entorno, sesion_admin).await;

    let usuario = common::registrar(&entorno, "mfa-confirmado@test.ellkan").await;
    let cuerpo = intentar_login(&entorno, &usuario).await;
    let sesion_parcial: Uuid = cuerpo["session_id"].as_str().unwrap().parse().unwrap();

    let resp = entorno
        .cliente
        .post(format!("{}/me/mfa/totp/setup", entorno.base))
        .bearer_auth(sesion_parcial)
        .send()
        .await
        .unwrap();
    let setup: Value = resp.json().await.unwrap();
    let secreto = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, setup["secret_base32"].as_str().unwrap())
        .unwrap();
    entorno
        .cliente
        .post(format!("{}/me/mfa/totp/confirm", entorno.base))
        .bearer_auth(sesion_parcial)
        .json(&json!({ "code": generar_codigo_actual(&secreto).to_string() }))
        .send()
        .await
        .unwrap();

    // Login siguiente: dispositivo ya conocido, TOTP ya confirmado -> pendiente_mfa.
    let cuerpo = intentar_login(&entorno, &usuario).await;
    assert_eq!(cuerpo["estado"], "pendiente_mfa");
    let sesion_b: Uuid = cuerpo["session_id"].as_str().unwrap().parse().unwrap();
    assert!(!puede_operar(&entorno, sesion_b).await);

    let resp = entorno
        .cliente
        .post(format!("{}/auth/mfa/verify", entorno.base))
        .bearer_auth(sesion_b)
        .json(&json!({ "code": generar_codigo_actual(&secreto).to_string() }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "el código correcto debería completar la sesión parcial");
    assert!(puede_operar(&entorno, sesion_b).await);
}

#[tokio::test]
async fn codigo_incorrecto_no_completa_la_sesion() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "mfa-admin-3@test.ellkan").await;
    let sesion_admin = common::login(&entorno, &admin).await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    activar_mfa_requerido(&entorno, sesion_admin).await;

    let usuario = common::registrar(&entorno, "mfa-codigo-malo@test.ellkan").await;
    let cuerpo = intentar_login(&entorno, &usuario).await;
    let sesion_parcial: Uuid = cuerpo["session_id"].as_str().unwrap().parse().unwrap();

    let resp = entorno
        .cliente
        .post(format!("{}/me/mfa/totp/setup", entorno.base))
        .bearer_auth(sesion_parcial)
        .send()
        .await
        .unwrap();
    let setup: Value = resp.json().await.unwrap();
    let secreto = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, setup["secret_base32"].as_str().unwrap())
        .unwrap();
    entorno
        .cliente
        .post(format!("{}/me/mfa/totp/confirm", entorno.base))
        .bearer_auth(sesion_parcial)
        .json(&json!({ "code": generar_codigo_actual(&secreto).to_string() }))
        .send()
        .await
        .unwrap();

    let cuerpo = intentar_login(&entorno, &usuario).await;
    let sesion_b: Uuid = cuerpo["session_id"].as_str().unwrap().parse().unwrap();

    let resp = entorno
        .cliente
        .post(format!("{}/auth/mfa/verify", entorno.base))
        .bearer_auth(sesion_b)
        .json(&json!({ "code": "000000" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
    assert!(!puede_operar(&entorno, sesion_b).await, "un código incorrecto no debería completar la sesión");
}

/// F-34: dos sesiones parciales concurrentes del mismo usuario (dos intentos
/// de login) tienen desafíos propios — verificar con la más vieja sigue
/// funcionando aunque exista una más nueva para el mismo usuario, porque el
/// binding compara por hash de sesión, no "el desafío más reciente".
#[tokio::test]
async fn verificar_encuentra_su_propio_desafio_entre_varias_sesiones_parciales() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "mfa-admin-4@test.ellkan").await;
    let sesion_admin = common::login(&entorno, &admin).await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    activar_mfa_requerido(&entorno, sesion_admin).await;

    let usuario = common::registrar(&entorno, "mfa-concurrente@test.ellkan").await;
    let cuerpo = intentar_login(&entorno, &usuario).await;
    let sesion_setup: Uuid = cuerpo["session_id"].as_str().unwrap().parse().unwrap();
    let resp = entorno
        .cliente
        .post(format!("{}/me/mfa/totp/setup", entorno.base))
        .bearer_auth(sesion_setup)
        .send()
        .await
        .unwrap();
    let setup: Value = resp.json().await.unwrap();
    let secreto = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, setup["secret_base32"].as_str().unwrap())
        .unwrap();
    entorno
        .cliente
        .post(format!("{}/me/mfa/totp/confirm", entorno.base))
        .bearer_auth(sesion_setup)
        .json(&json!({ "code": generar_codigo_actual(&secreto).to_string() }))
        .send()
        .await
        .unwrap();

    // Dos intentos de login concurrentes -> dos sesiones parciales + dos
    // desafíos distintos para el mismo usuario.
    let cuerpo_a = intentar_login(&entorno, &usuario).await;
    let sesion_a: Uuid = cuerpo_a["session_id"].as_str().unwrap().parse().unwrap();
    let cuerpo_b = intentar_login(&entorno, &usuario).await;
    let sesion_b: Uuid = cuerpo_b["session_id"].as_str().unwrap().parse().unwrap();
    assert_ne!(sesion_a, sesion_b);

    // Verificar con la sesión A (la más vieja) debe encontrar SU propio
    // desafío, no fallar porque exista uno más nuevo (B) para el mismo user.
    let resp = entorno
        .cliente
        .post(format!("{}/auth/mfa/verify", entorno.base))
        .bearer_auth(sesion_a)
        .json(&json!({ "code": generar_codigo_actual(&secreto).to_string() }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert!(puede_operar(&entorno, sesion_a).await);
    // B sigue parcial — verificar A no la afecta.
    assert!(!puede_operar(&entorno, sesion_b).await);
}

#[tokio::test]
async fn rate_limit_dedicado_de_mfa_verify() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "mfa-admin-5@test.ellkan").await;
    let sesion_admin = common::login(&entorno, &admin).await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    activar_mfa_requerido(&entorno, sesion_admin).await;

    let usuario = common::registrar(&entorno, "mfa-rate-limit@test.ellkan").await;
    let cuerpo = intentar_login(&entorno, &usuario).await;
    let sesion_parcial: Uuid = cuerpo["session_id"].as_str().unwrap().parse().unwrap();
    let resp = entorno
        .cliente
        .post(format!("{}/me/mfa/totp/setup", entorno.base))
        .bearer_auth(sesion_parcial)
        .send()
        .await
        .unwrap();
    let setup: Value = resp.json().await.unwrap();
    let secreto = base32::decode(base32::Alphabet::Rfc4648 { padding: false }, setup["secret_base32"].as_str().unwrap())
        .unwrap();
    entorno
        .cliente
        .post(format!("{}/me/mfa/totp/confirm", entorno.base))
        .bearer_auth(sesion_parcial)
        .json(&json!({ "code": generar_codigo_actual(&secreto).to_string() }))
        .send()
        .await
        .unwrap();

    let cuerpo = intentar_login(&entorno, &usuario).await;
    let sesion_b: Uuid = cuerpo["session_id"].as_str().unwrap().parse().unwrap();

    let mut vio_429 = false;
    for _ in 0..10 {
        let resp = entorno
            .cliente
            .post(format!("{}/auth/mfa/verify", entorno.base))
            .bearer_auth(sesion_b)
            .json(&json!({ "code": "000000" }))
            .send()
            .await
            .unwrap();
        if resp.status() == 429 {
            vio_429 = true;
            break;
        }
    }
    assert!(vio_429, "10 intentos rápidos con código incorrecto deberían agotar el rate limit dedicado");
}

#[tokio::test]
async fn admin_mfa_policy_rechaza_webauthn_y_permite_totp() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "mfa-admin-6@test.ellkan").await;
    let sesion_admin = common::login(&entorno, &admin).await;
    common::promover_admin(&entorno.pool, admin.user_id).await;

    let resp = entorno
        .cliente
        .put(format!("{}/admin/mfa-policy", entorno.base))
        .bearer_auth(sesion_admin)
        .json(&json!({ "require_mfa": true, "allowed_methods": ["webauthn"], "grace_period_days": 7 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "webauthn como segundo factor no está implementado, debe rechazarse");

    let resp = entorno
        .cliente
        .get(format!("{}/admin/mfa-policy", entorno.base))
        .bearer_auth(sesion_admin)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["require_mfa"], false, "el intento rechazado no debería haber aplicado nada");
}

#[tokio::test]
async fn no_admin_no_puede_leer_ni_cambiar_la_politica_de_mfa() {
    let entorno = common::levantar().await;
    let usuario = common::registrar(&entorno, "mfa-no-admin@test.ellkan").await;
    let sesion = common::login(&entorno, &usuario).await;

    let resp = entorno.cliente.get(format!("{}/admin/mfa-policy", entorno.base)).bearer_auth(sesion).send().await.unwrap();
    assert_eq!(resp.status(), 403);
}
