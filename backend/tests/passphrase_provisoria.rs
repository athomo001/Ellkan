// Autor: Athan Espinoza

//! Passphrase provisoria: un usuario creado por un admin (`POST /admin/users`)
//! debe cambiar la passphrase antes de poder operar — enforcement real
//! server-side (sesión parcial + `SesionValida`), no sólo una recomendación
//! de la UI.

mod common;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::Signer;
use ellkan_crypto::claves::{KeypairAcuerdo, KeypairFirma};
use ellkan_crypto::clave_privada;
use ellkan_crypto::secretos::PassphraseSecreta;
use secrecy::SecretBox;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Arma la ceremonia de identidad completa (mismo criterio que
/// `crearUsuarioPorAdmin` en `$lib/crypto/identity.ts`: el admin conoce la
/// passphrase temporal a propósito) y llama `POST /admin/users`.
async fn crear_usuario_por_admin(entorno: &common::Entorno, sesion_admin: Uuid, email: &str) -> common::Usuario {
    let x25519 = KeypairAcuerdo::generar();
    let ed25519 = KeypairFirma::generar();
    let passphrase: PassphraseSecreta = SecretBox::new(Box::new("passphrase-provisoria-temporal".to_string()));

    let mut privadas = [0u8; 64];
    privadas[..32].copy_from_slice(x25519.privada().to_bytes().as_slice());
    privadas[32..].copy_from_slice(&ed25519.firmante().to_bytes());
    let salt: [u8; 16] = ellkan_crypto::aleatoriedad::bytes_aleatorios();
    let blob = clave_privada::cifrar_clave_privada(&passphrase, salt, &privadas, email.as_bytes()).unwrap();

    let resp = entorno
        .cliente
        .post(format!("{}/admin/users", entorno.base))
        .bearer_auth(sesion_admin)
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
    let status = resp.status();
    let texto = resp.text().await.unwrap();
    assert_eq!(status, 200, "POST /admin/users debería funcionar, body: {texto}");
    let cuerpo: Value = serde_json::from_str(&texto).unwrap();
    let user_id: Uuid = cuerpo["user_id"].as_str().unwrap().parse().unwrap();
    assert_eq!(cuerpo["pending_verification"], false, "un admin ya vouches por el email, nace verificado");

    let device_token: [u8; 32] = ellkan_crypto::aleatoriedad::bytes_aleatorios();
    common::Usuario { email: email.to_string(), user_id, x25519, ed25519, passphrase, device_token }
}

/// Como `common::login`, pero devuelve el `estado` real en vez de asumir
/// "completo" — necesario acá porque el estado esperado tras crear por
/// admin es `requiere_cambiar_passphrase`, no `completo`.
async fn login_y_estado(entorno: &common::Entorno, usuario: &common::Usuario) -> (String, Uuid) {
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
        let estado = cuerpo["estado"].as_str().unwrap().to_string();
        let session_id: Uuid = cuerpo["session_id"].as_str().unwrap().parse().unwrap();
        return (estado, session_id);
    }

    let device_challenge_id = cuerpo["device_challenge_id"].as_str().unwrap();
    let codigo = codigo_de_dispositivo_encolado(&entorno.pool, &usuario.email).await;

    let resp = entorno
        .cliente
        .post(format!("{}/auth/verify-device", entorno.base))
        .json(&json!({ "device_challenge_id": device_challenge_id, "code": codigo }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cuerpo: Value = resp.json().await.unwrap();
    let estado = cuerpo["estado"].as_str().unwrap().to_string();
    let session_id: Uuid = cuerpo["session_id"].as_str().unwrap().parse().unwrap();
    (estado, session_id)
}

async fn codigo_de_dispositivo_encolado(pool: &sqlx::PgPool, email: &str) -> String {
    for _ in 0..20 {
        if let Ok(fila) = sqlx::query_as::<_, (String,)>(
            "select body from outbound_emails where recipient = $1 and subject = $2 order by created_at desc limit 1",
        )
        .bind(email)
        .bind("Ellkan: verificá este dispositivo nuevo")
        .fetch_one(pool)
        .await
        {
            return fila.0.lines().find_map(|l| l.strip_prefix("Código de verificación: ")).unwrap().trim().to_string();
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("debería haber un email de verificación de dispositivo encolado");
}

async fn puede_operar(entorno: &common::Entorno, sesion: Uuid) -> bool {
    entorno.cliente.get(format!("{}/resources", entorno.base)).bearer_auth(sesion).send().await.unwrap().status() == 200
}

#[tokio::test]
async fn admin_crea_usuario_y_login_exige_cambiar_la_passphrase_antes_de_operar() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin-provisoria@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    let usuario = crear_usuario_por_admin(&entorno, sesion_admin, "provisoria@test.ellkan").await;

    let fila: (bool,) = sqlx::query_as("select must_change_passphrase from users where id = $1")
        .bind(usuario.user_id)
        .fetch_one(&entorno.pool)
        .await
        .unwrap();
    assert!(fila.0, "un usuario creado por admin debe nacer con must_change_passphrase = true");

    let (estado, sesion_parcial) = login_y_estado(&entorno, &usuario).await;
    assert_eq!(estado, "requiere_cambiar_passphrase");
    assert!(!puede_operar(&entorno, sesion_parcial).await, "una sesión parcial por passphrase provisoria no debe poder operar");

    // Cambiar la passphrase con la sesión parcial (SesionValida acepta esto
    // a propósito) — mismo material, sólo se re-envuelve con la nueva.
    let mut privadas = [0u8; 64];
    privadas[..32].copy_from_slice(usuario.x25519.privada().to_bytes().as_slice());
    privadas[32..].copy_from_slice(&usuario.ed25519.firmante().to_bytes());
    let nueva_passphrase: PassphraseSecreta = SecretBox::new(Box::new("passphrase-definitiva-elegida-por-mi".to_string()));
    let nueva_salt: [u8; 16] = ellkan_crypto::aleatoriedad::bytes_aleatorios();
    let nuevo_blob =
        clave_privada::cifrar_clave_privada(&nueva_passphrase, nueva_salt, &privadas, usuario.email.as_bytes()).unwrap();

    let resp = entorno
        .cliente
        .post(format!("{}/me/change-passphrase", entorno.base))
        .bearer_auth(sesion_parcial)
        .json(&json!({
            "encrypted_private_key_blob_b64": B64.encode(&nuevo_blob.envoltura.ciphertext),
            "private_key_nonce_b64": B64.encode(nuevo_blob.envoltura.nonce),
            "kdf_salt_b64": B64.encode(nuevo_blob.salt),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "una sesión parcial (SesionValida) debería poder cambiar la passphrase");

    // La sesión parcial murió (misma rotación de security_stamp de siempre).
    assert!(!puede_operar(&entorno, sesion_parcial).await);

    let fila: (bool,) = sqlx::query_as("select must_change_passphrase from users where id = $1")
        .bind(usuario.user_id)
        .fetch_one(&entorno.pool)
        .await
        .unwrap();
    assert!(!fila.0, "cambiar la passphrase debe limpiar must_change_passphrase");

    // Login de nuevo (dispositivo ya conocido, sin política MFA activa) debe
    // completar directo — el requisito ya no aplica.
    let (estado, _sesion) = login_y_estado(&entorno, &usuario).await;
    assert_eq!(estado, "completo", "tras cambiar la passphrase, el próximo login debe completar normalmente");
}

#[tokio::test]
async fn auto_registro_no_exige_cambiar_la_passphrase() {
    let entorno = common::levantar().await;
    let usuario = common::registrar(&entorno, "auto-registro-normal@test.ellkan").await;

    let fila: (bool,) = sqlx::query_as("select must_change_passphrase from users where id = $1")
        .bind(usuario.user_id)
        .fetch_one(&entorno.pool)
        .await
        .unwrap();
    assert!(!fila.0, "un auto-registro nunca debe nacer con must_change_passphrase = true");

    let (estado, _sesion) = login_y_estado(&entorno, &usuario).await;
    assert_eq!(estado, "completo");
}
