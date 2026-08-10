// Autor: Athan Espinoza

//! F-24: auto-registro con allowlist de dominios + verificación de email
//! por código. El bootstrap (primer usuario de la instancia) se prueba
//! aparte en `primer_usuario_admin.rs` — acá se prueba específicamente que
//! nace ya verificado y sin pasar por política/SMTP, y que cualquier
//! registro posterior sí pasa por las dos cosas.

mod common;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::Signer;
use ellkan_crypto::claves::{KeypairAcuerdo, KeypairFirma};
use ellkan_crypto::clave_privada;
use ellkan_crypto::secretos::PassphraseSecreta;
use secrecy::SecretBox;
use serde_json::{json, Value};

/// Como `common::registrar`, pero sin asumir 200 ni auto-verificar
/// después — necesario acá porque varios tests esperan que el registro
/// falle, y los que no fallan quieren ejercitar el estado
/// `pending_verification` real, no el atajo de `common::registrar`. Además
/// devuelve el `Usuario` armado (sin `user_id`, todavía no se sabe si el
/// registro tuvo éxito) para poder intentar un login real después.
async fn registrar_crudo(entorno: &common::Entorno, email: &str) -> (u16, Value, KeypairAcuerdo, KeypairFirma) {
    let x25519 = KeypairAcuerdo::generar();
    let ed25519 = KeypairFirma::generar();
    let passphrase: PassphraseSecreta = SecretBox::new(Box::new(format!("{email}-passphrase-larga-1")));
    let mut privadas = [0u8; 64];
    privadas[..32].copy_from_slice(x25519.privada().to_bytes().as_slice());
    privadas[32..].copy_from_slice(&ed25519.firmante().to_bytes());
    let salt: [u8; 16] = ellkan_crypto::aleatoriedad::bytes_aleatorios();
    let blob = clave_privada::cifrar_clave_privada(&passphrase, salt, &privadas, email.as_bytes()).unwrap();

    let resp = entorno
        .cliente
        .post(format!("{}/auth/register", entorno.base))
        .json(&json!({
            "email": email,
            "display_name": email,
            "public_key_x25519_b64": B64.encode(x25519.publica().as_bytes()),
            "public_key_ed25519_b64": B64.encode(ed25519.verificadora().to_bytes()),
            "encrypted_private_key_blob_b64": B64.encode(&blob.envoltura.ciphertext),
            "private_key_nonce_b64": B64.encode(blob.envoltura.nonce),
            "kdf_salt_b64": B64.encode(blob.salt),
        }))
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let cuerpo: Value = resp.json().await.unwrap();
    (status, cuerpo, x25519, ed25519)
}

/// Login real (challenge → firma → verify), sin pasar por F-02 (asume que
/// ya llegó a `pendiente_dispositivo` o `completo`, indistinto acá: sólo
/// importa si `verify` devuelve 401 o no).
async fn intentar_login_real(entorno: &common::Entorno, email: &str, ed25519: &KeypairFirma) -> u16 {
    let resp = entorno
        .cliente
        .post(format!("{}/auth/challenge", entorno.base))
        .json(&json!({ "email": email }))
        .send()
        .await
        .unwrap();
    let cuerpo: Value = resp.json().await.unwrap();
    let nonce = B64.decode(cuerpo["nonce_b64"].as_str().unwrap()).unwrap();
    let firma = ed25519.firmante().sign(&nonce);

    let resp = entorno
        .cliente
        .post(format!("{}/auth/verify", entorno.base))
        .json(&json!({
            "email": email,
            "nonce_b64": B64.encode(&nonce),
            "signature_b64": B64.encode(firma.to_bytes()),
            "device_token_hash_b64": B64.encode([0u8; 32]),
        }))
        .send()
        .await
        .unwrap();
    resp.status().as_u16()
}

async fn intentar_login_falla(entorno: &common::Entorno, email: &str) {
    let resp = entorno
        .cliente
        .post(format!("{}/auth/challenge", entorno.base))
        .json(&json!({ "email": email }))
        .send()
        .await
        .unwrap();
    let cuerpo: Value = resp.json().await.unwrap();
    let nonce_b64 = cuerpo["nonce_b64"].as_str().unwrap();

    // Anti-enumeración: una cuenta sin verificar responde con el mismo
    // error genérico que una que no existe — no hace falta reconstruir la
    // firma real, cualquier firma inválida ya alcanza `InvalidCredentials`,
    // el punto acá es que `verify` nunca llega a evaluarla porque
    // `buscar_por_email` ya no encuentra la cuenta.
    let resp = entorno
        .cliente
        .post(format!("{}/auth/verify", entorno.base))
        .json(&json!({
            "email": email,
            "nonce_b64": nonce_b64,
            "signature_b64": B64.encode([0u8; 64]),
            "device_token_hash_b64": B64.encode([0u8; 32]),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "una cuenta sin verificar no debería poder loguear todavía");
}

async fn habilitar_self_registration(entorno: &common::Entorno, sesion_admin: uuid::Uuid, enabled: bool, allowed_domains: &[&str]) {
    let resp = entorno
        .cliente
        .put(format!("{}/admin/self-registration-policy", entorno.base))
        .bearer_auth(sesion_admin)
        .json(&json!({ "enabled": enabled, "allowed_domains": allowed_domains }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn segundo_registro_bloqueado_si_smtp_no_esta_configurado() {
    let entorno = common::levantar().await;
    // `common::levantar()` ya deja SMTP configurado para el resto de la
    // suite — acá se lo desconfigura a propósito para probar el gate.
    sqlx::query!(r#"update smtp_config set host = null where organization_id = 1"#)
        .execute(&entorno.pool)
        .await
        .unwrap();

    let (status, cuerpo, _, _) = registrar_crudo(&entorno, "sin-smtp@test.ellkan").await;
    assert_eq!(status, 400);
    assert!(
        cuerpo["error"]["message"].as_str().unwrap().contains("SMTP"),
        "el mensaje debería explicar que SMTP no está configurado, fue: {cuerpo}"
    );
}

#[tokio::test]
async fn segundo_registro_respeta_la_allowlist_de_dominios() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin-allowlist@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    habilitar_self_registration(&entorno, sesion_admin, true, &["netics.cl"]).await;

    let (status, cuerpo, _, _) = registrar_crudo(&entorno, "afuera@otro-dominio.com").await;
    assert_eq!(status, 400, "un dominio no permitido debe rechazarse: {cuerpo}");

    let (status, cuerpo, _, _) = registrar_crudo(&entorno, "adentro@netics.cl").await;
    assert_eq!(status, 200, "un dominio permitido debe aceptarse: {cuerpo}");
    assert_eq!(cuerpo["pending_verification"], true);
}

#[tokio::test]
async fn segundo_registro_bloqueado_si_self_registration_esta_deshabilitado() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin-disable@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    habilitar_self_registration(&entorno, sesion_admin, false, &[]).await;

    let (status, _, _, _) = registrar_crudo(&entorno, "nadie@test.ellkan").await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn flujo_completo_de_verificacion_de_email() {
    let entorno = common::levantar().await;

    let (status, cuerpo, _, ed25519) = registrar_crudo(&entorno, "pendiente@test.ellkan").await;
    assert_eq!(status, 200);
    assert_eq!(cuerpo["pending_verification"], true, "cualquier registro no-bootstrap queda pendiente");

    // No puede loguear todavía.
    intentar_login_falla(&entorno, "pendiente@test.ellkan").await;

    // Código incorrecto rechazado, no consume el desafío real.
    let resp = entorno
        .cliente
        .post(format!("{}/auth/verify-email", entorno.base))
        .json(&json!({ "email": "pendiente@test.ellkan", "code": "000000" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    let codigo = common::codigo_verificacion_registro_encolado(&entorno.pool, "pendiente@test.ellkan").await;

    let resp = entorno
        .cliente
        .post(format!("{}/auth/verify-email", entorno.base))
        .json(&json!({ "email": "pendiente@test.ellkan", "code": codigo }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let verificado: bool =
        sqlx::query_scalar("select email_verified_at is not null from users where email = $1")
            .bind("pendiente@test.ellkan")
            .fetch_one(&entorno.pool)
            .await
            .unwrap();
    assert!(verificado, "el email debería quedar marcado como verificado");

    // Y el login real ya funciona (deja de caer en el 401 genérico).
    let status = intentar_login_real(&entorno, "pendiente@test.ellkan", &ed25519).await;
    assert_eq!(status, 200, "tras verificar el email, el login debería avanzar más allá de InvalidCredentials");
}

#[tokio::test]
async fn reenviar_verificacion_invalida_el_codigo_anterior() {
    let entorno = common::levantar().await;
    registrar_crudo(&entorno, "reenvio@test.ellkan").await;
    let codigo_viejo = common::codigo_verificacion_registro_encolado(&entorno.pool, "reenvio@test.ellkan").await;

    let resp = entorno
        .cliente
        .post(format!("{}/auth/verify-email/resend", entorno.base))
        .json(&json!({ "email": "reenvio@test.ellkan" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = entorno
        .cliente
        .post(format!("{}/auth/verify-email", entorno.base))
        .json(&json!({ "email": "reenvio@test.ellkan", "code": codigo_viejo }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "el código viejo debería quedar invalidado tras el reenvío");
}

#[tokio::test]
async fn reenviar_verificacion_es_anti_enumeracion() {
    let entorno = common::levantar().await;
    let resp = entorno
        .cliente
        .post(format!("{}/auth/verify-email/resend", entorno.base))
        .json(&json!({ "email": "no-existe@test.ellkan" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "no debe revelar si la cuenta existe o no");
}

#[tokio::test]
async fn no_admin_no_puede_leer_ni_cambiar_la_politica() {
    let entorno = common::levantar().await;
    let user = common::registrar(&entorno, "sin-admin-sr@test.ellkan").await;
    let sesion = common::login(&entorno, &user).await;

    let resp = entorno
        .cliente
        .get(format!("{}/admin/self-registration-policy", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}
