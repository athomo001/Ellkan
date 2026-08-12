// Autor: Athan Espinoza

//! Recovery kit: generar/regenerar, pedir reset por email (sin sesión),
//! verificar token + segundo factor (TOTP si está confirmado, email si no),
//! completar de forma atómica — y que el kit usado quede marcado para
//! rotar en el próximo login.

mod common;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ellkan_crypto::claves::KeypairAcuerdo;
use ellkan_crypto::clave_privada;
use ellkan_crypto::sellado;
use ed25519_dalek::Signer;
use ellkan_crypto::secretos::PassphraseSecreta;
use secrecy::SecretBox;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn generar_codigo_actual(secreto: &[u8]) -> u32 {
    let ahora = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
    ellkan_crypto::totp::codigo_totp(secreto, ahora)
}

/// Configura y confirma TOTP de login sobre una sesión ya completa — mismo
/// flujo que `tests/mfa.rs`, reusado acá porque el segundo factor del
/// recovery kit depende de si el usuario tiene un TOTP confirmado, sin
/// importar la política MFA de la organización.
async fn configurar_totp(entorno: &common::Entorno, sesion: Uuid) -> Vec<u8> {
    let resp =
        entorno.cliente.post(format!("{}/me/mfa/totp/setup", entorno.base)).bearer_auth(sesion).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let cuerpo: Value = resp.json().await.unwrap();
    let secreto =
        base32::decode(base32::Alphabet::Rfc4648 { padding: false }, cuerpo["secret_base32"].as_str().unwrap())
            .unwrap();

    let resp = entorno
        .cliente
        .post(format!("{}/me/mfa/totp/confirm", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({ "code": generar_codigo_actual(&secreto).to_string() }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    secreto
}

/// Material de identidad real del usuario (X25519 priv || Ed25519 priv, 64
/// bytes) — lo mismo que `sealed_identity_material` protege, mismo convenio
/// que `account_recovery`'s `sealed_private_key_for_org`.
fn material_de_identidad(usuario: &common::Usuario) -> [u8; 64] {
    let mut material = [0u8; 64];
    material[..32].copy_from_slice(usuario.x25519.privada().to_bytes().as_slice());
    material[32..].copy_from_slice(&usuario.ed25519.firmante().to_bytes());
    material
}

async fn generar_kit(entorno: &common::Entorno, sesion: Uuid, material: &[u8; 64]) -> KeypairAcuerdo {
    let kit = KeypairAcuerdo::generar();
    let sellado = sellado::sellar_bytes(kit.publica(), material);

    let resp = entorno
        .cliente
        .put(format!("{}/me/recovery-kit", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({
            "kit_public_key_x25519_b64": B64.encode(kit.publica().as_bytes()),
            "sealed_identity_material_b64": B64.encode(&sellado),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "generar el kit debería funcionar con una sesión válida");
    kit
}

async fn token_de_reset_encolado(pool: &sqlx::PgPool, email: &str) -> String {
    for _ in 0..20 {
        if let Ok(fila) = sqlx::query_as::<_, (String,)>(
            "select body from outbound_emails where recipient = $1 and subject = $2 order by created_at desc limit 1",
        )
        .bind(email)
        .bind("Ellkan: recuperá el acceso a tu cuenta")
        .fetch_one(pool)
        .await
        {
            let linea = fila.0.lines().find(|l| l.contains("token=")).expect("el body debe traer el link con token");
            return linea.rsplit("token=").next().unwrap().trim().to_string();
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("debería haber un email de reset de recovery kit encolado");
}

/// Como `common::login`, pero para un dispositivo YA conocido (segundo
/// login del mismo `Usuario` dentro de un mismo test) — a diferencia de
/// `common::login`, que siempre asume un `device_token` nunca visto y
/// exige `pendiente_dispositivo`, acá el login real completa directo.
async fn login_dispositivo_conocido(entorno: &common::Entorno, usuario: &common::Usuario) -> Uuid {
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
    assert_eq!(cuerpo["estado"], "completo", "dispositivo ya conocido, sin política MFA activa, debe completar directo");
    cuerpo["session_id"].as_str().unwrap().parse().unwrap()
}

async fn codigo_mfa_encolado(pool: &sqlx::PgPool, email: &str) -> String {
    for _ in 0..20 {
        if let Ok(fila) = sqlx::query_as::<_, (String,)>(
            "select body from outbound_emails where recipient = $1 and subject = $2 order by created_at desc limit 1",
        )
        .bind(email)
        .bind("Ellkan: tu código de verificación")
        .fetch_one(pool)
        .await
        {
            return fila.0.lines().find_map(|l| l.strip_prefix("Código de verificación: ")).unwrap().trim().to_string();
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("debería haber un email de código de recovery kit encolado");
}

#[tokio::test]
async fn generar_kit_y_estado_lo_refleja() {
    let entorno = common::levantar().await;
    let user = common::registrar(&entorno, "estado-kit@test.ellkan").await;
    let sesion = common::login(&entorno, &user).await;

    let resp =
        entorno.cliente.get(format!("{}/me/recovery-kit", entorno.base)).bearer_auth(sesion).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["configured"], false);
    assert_eq!(cuerpo["must_rotate"], false);

    let material = material_de_identidad(&user);
    generar_kit(&entorno, sesion, &material).await;

    let resp =
        entorno.cliente.get(format!("{}/me/recovery-kit", entorno.base)).bearer_auth(sesion).send().await.unwrap();
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["configured"], true);
    assert_eq!(cuerpo["must_rotate"], false);
    assert!(cuerpo["created_at"].is_string());
}

#[tokio::test]
async fn reset_sin_kit_configurado_da_404() {
    let entorno = common::levantar().await;
    let user = common::registrar(&entorno, "sin-kit@test.ellkan").await;

    let resp = entorno
        .cliente
        .post(format!("{}/recovery-kit/reset", entorno.base))
        .json(&json!({ "email": user.email }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "sin kit configurado no hay forma de resetear (anti-enumeración)");

    let resp = entorno
        .cliente
        .post(format!("{}/recovery-kit/reset", entorno.base))
        .json(&json!({ "email": "no-existe@test.ellkan" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "mismo código para un email inexistente — anti-enumeración");
}

#[tokio::test]
async fn flujo_completo_de_reset_con_totp_y_kit_queda_marcado_para_rotar() {
    let entorno = common::levantar().await;
    let victima = common::registrar(&entorno, "reset-totp@test.ellkan").await;
    let sesion = common::login(&entorno, &victima).await;

    let secreto_totp = configurar_totp(&entorno, sesion).await;
    let material = material_de_identidad(&victima);
    let kit = generar_kit(&entorno, sesion, &material).await;

    let resp = entorno
        .cliente
        .post(format!("{}/recovery-kit/reset", entorno.base))
        .json(&json!({ "email": victima.email }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let token = token_de_reset_encolado(&entorno.pool, &victima.email).await;

    let resp = entorno
        .cliente
        .get(format!("{}/recovery-kit/reset/{token}", entorno.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["mfa_method"], "totp", "usuario con TOTP confirmado siempre verifica con TOTP");
    let sellado_b64 = cuerpo["sealed_identity_material_b64"].as_str().unwrap();

    // Cliente: desella con la privada del kit, confirma que es el material
    // original, y re-sella con una passphrase nueva.
    let sellado_bytes = B64.decode(sellado_b64).unwrap();
    let abierto = sellado::abrir_bytes(kit.privada(), &sellado_bytes).unwrap();
    assert_eq!(abierto, material);

    let nueva_passphrase: PassphraseSecreta = SecretBox::new(Box::new("passphrase-post-recovery-kit".to_string()));
    let nueva_salt: [u8; 16] = ellkan_crypto::aleatoriedad::bytes_aleatorios();
    let nuevo_blob =
        clave_privada::cifrar_clave_privada(&nueva_passphrase, nueva_salt, &abierto, victima.email.as_bytes()).unwrap();

    let body_completar = json!({
        "mfa_code": "000000",
        "encrypted_private_key_blob_b64": B64.encode(&nuevo_blob.envoltura.ciphertext),
        "private_key_nonce_b64": B64.encode(nuevo_blob.envoltura.nonce),
        "kdf_salt_b64": B64.encode(nuevo_blob.salt),
    });

    // Código incorrecto: falla, y el token sigue vigente para reintentar.
    let resp = entorno
        .cliente
        .post(format!("{}/recovery-kit/reset/{token}/complete", entorno.base))
        .json(&body_completar)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "un código TOTP incorrecto no debería completar el reset");

    let mut body_ok = body_completar.clone();
    body_ok["mfa_code"] = json!(generar_codigo_actual(&secreto_totp).to_string());

    let resp = entorno
        .cliente
        .post(format!("{}/recovery-kit/reset/{token}/complete", entorno.base))
        .json(&body_ok)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let texto = resp.text().await.unwrap();
    assert_eq!(status, 200, "el código TOTP correcto debería completar el reset, body: {texto}");

    // La sesión vieja quedó invalidada (misma rotación de `security_stamp`
    // que F-16 ya usa vía `CambiarPassphraseService`).
    let resp = entorno.cliente.get(format!("{}/me", entorno.base)).bearer_auth(sesion).send().await.unwrap();
    assert_eq!(resp.status(), 401, "completar el reset invalida cualquier sesión vieja");

    // El token ya consumido no puede reusarse — `buscar_vigente_por_hash`
    // ya lo excluye (`consumed_at is null`), así que el segundo intento ni
    // siquiera encuentra el token, no llega a la etapa de marcarlo.
    let resp = entorno
        .cliente
        .post(format!("{}/recovery-kit/reset/{token}/complete", entorno.base))
        .json(&body_ok)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "un token ya consumido no puede reusarse");

    // Login de nuevo (mismo Ed25519, la identidad no cambió — sólo se
    // re-envolvió con la passphrase nueva) para chequear `must_rotate`.
    let sesion_nueva = login_dispositivo_conocido(&entorno, &victima).await;
    let resp = entorno
        .cliente
        .get(format!("{}/me/recovery-kit", entorno.base))
        .bearer_auth(sesion_nueva)
        .send()
        .await
        .unwrap();
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["must_rotate"], true, "el kit recién usado debe quedar marcado para rotar");

    // Regenerar limpia `must_rotate`.
    generar_kit(&entorno, sesion_nueva, &material).await;
    let resp = entorno
        .cliente
        .get(format!("{}/me/recovery-kit", entorno.base))
        .bearer_auth(sesion_nueva)
        .send()
        .await
        .unwrap();
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["must_rotate"], false, "regenerar el kit limpia la marca de rotación");
}

#[tokio::test]
async fn flujo_de_reset_sin_totp_cae_a_codigo_por_email() {
    let entorno = common::levantar().await;
    let victima = common::registrar(&entorno, "reset-email@test.ellkan").await;
    let sesion = common::login(&entorno, &victima).await;

    let material = material_de_identidad(&victima);
    let kit = generar_kit(&entorno, sesion, &material).await;

    entorno
        .cliente
        .post(format!("{}/recovery-kit/reset", entorno.base))
        .json(&json!({ "email": victima.email }))
        .send()
        .await
        .unwrap();
    let token = token_de_reset_encolado(&entorno.pool, &victima.email).await;

    let resp = entorno.cliente.get(format!("{}/recovery-kit/reset/{token}", entorno.base)).send().await.unwrap();
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["mfa_method"], "email", "sin TOTP confirmado, el fallback es un código por email");
    let sellado_bytes = B64.decode(cuerpo["sealed_identity_material_b64"].as_str().unwrap()).unwrap();
    let abierto = sellado::abrir_bytes(kit.privada(), &sellado_bytes).unwrap();

    let resp = entorno
        .cliente
        .post(format!("{}/recovery-kit/reset/{token}/email-code", entorno.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let codigo = codigo_mfa_encolado(&entorno.pool, &victima.email).await;

    let nueva_passphrase: PassphraseSecreta = SecretBox::new(Box::new("otra-passphrase-post-kit-email".to_string()));
    let nueva_salt: [u8; 16] = ellkan_crypto::aleatoriedad::bytes_aleatorios();
    let nuevo_blob =
        clave_privada::cifrar_clave_privada(&nueva_passphrase, nueva_salt, &abierto, victima.email.as_bytes()).unwrap();

    let resp = entorno
        .cliente
        .post(format!("{}/recovery-kit/reset/{token}/complete", entorno.base))
        .json(&json!({
            "mfa_code": codigo,
            "encrypted_private_key_blob_b64": B64.encode(&nuevo_blob.envoltura.ciphertext),
            "private_key_nonce_b64": B64.encode(nuevo_blob.envoltura.nonce),
            "kdf_salt_b64": B64.encode(nuevo_blob.salt),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "el código por email correcto debería completar el reset");
}
