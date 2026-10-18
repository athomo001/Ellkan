// Autor: Athan Espinoza

//! `rate_limit::limitar_solicitudes`: con sesión válida cuenta el cupo del
//! usuario (20/s, ráfaga 300) y NO el de la IP; sin sesión, o con un token
//! inventado, cuenta el de la IP (10/s, ráfaga 250).

mod common;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::Signer;
use ellkan_crypto::claves::{KeypairAcuerdo, KeypairFirma};
use ellkan_crypto::clave_privada;
use ellkan_crypto::secretos::PassphraseSecreta;
use secrecy::SecretBox;
use serde_json::{json, Value};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::ImageExt;

#[tokio::test]
async fn mismo_usuario_supera_el_limite_por_usuario_y_recibe_429() {
    let contenedor = Postgres::default()
        .with_db_name("ellkan")
        .with_user("postgres")
        .with_password("postgres")
        .with_tag("18")
        .start()
        .await
        .expect("levantar Postgres 18 en un contenedor");

    let puerto = contenedor.get_host_port_ipv4(5432).await.unwrap();
    let database_url = format!("postgres://postgres:postgres@127.0.0.1:{puerto}/ellkan");

    let secrets_key: SecretBox<[u8; 32]> = SecretBox::new(Box::new(ellkan_crypto::aleatoriedad::bytes_aleatorios()));
    let estado = ellkan_backend::construir_estado(&database_url, secrets_key)
        .await
        .expect("migrar y conectar");
    let pool = estado.pool.clone();

    // Parte A/B: sin SMTP configurado, F-02 auto-verifica el dispositivo sin
    // pedir código — este test depende del flujo real (`pendiente_dispositivo`
    // + `verify-device`), mismo criterio que `common/mod.rs::levantar()`.
    sqlx::query!(
        r#"update smtp_config set host = 'smtp.invalid', port = 25, from_address = 'no-reply@ellkan.test' where organization_id = 1"#
    )
    .execute(&pool)
    .await
    .expect("seedear smtp_config para los tests");

    let app = ellkan_backend::construir_router(estado);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await
            .unwrap();
    });
    let base = format!("http://{addr}");
    let cliente = reqwest::Client::new();

    // --- Registro + login de un solo usuario ---
    let email = "rate-limit@test.ellkan";
    let x25519 = KeypairAcuerdo::generar();
    let ed25519 = KeypairFirma::generar();
    let passphrase: PassphraseSecreta = SecretBox::new(Box::new("passphrase-de-prueba-larga".to_string()));
    let mut privadas = [0u8; 64];
    privadas[..32].copy_from_slice(x25519.privada().to_bytes().as_slice());
    privadas[32..].copy_from_slice(&ed25519.firmante().to_bytes());
    let salt: [u8; 16] = ellkan_crypto::aleatoriedad::bytes_aleatorios();
    let blob = clave_privada::cifrar_clave_privada(&passphrase, salt, &privadas, email.as_bytes()).unwrap();

    let resp = cliente
        .post(format!("{base}/auth/register"))
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
    assert_eq!(resp.status(), 200);

    let resp = cliente
        .post(format!("{base}/auth/challenge"))
        .json(&json!({ "email": email }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cuerpo: Value = resp.json().await.unwrap();
    let nonce = B64.decode(cuerpo["nonce_b64"].as_str().unwrap()).unwrap();
    let firma = ed25519.firmante().sign(&nonce);

    use sha2::{Digest, Sha256};
    let device_token: [u8; 32] = ellkan_crypto::aleatoriedad::bytes_aleatorios();
    let device_token_hash_b64 = B64.encode(Sha256::digest(device_token));

    let resp = cliente
        .post(format!("{base}/auth/verify"))
        .json(&json!({
            "email": email,
            "nonce_b64": B64.encode(&nonce),
            "signature_b64": B64.encode(firma.to_bytes()),
            "device_token_hash_b64": device_token_hash_b64,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["estado"], "pendiente_dispositivo");
    let device_challenge_id = cuerpo["device_challenge_id"].as_str().unwrap();

    // Dispositivo nunca visto -> hay que "leer el email" (stub, ver
    // notificaciones.rs). Se encola de forma asíncrona: el helper reintenta
    // (antes se leía una sola vez y el test fallaba con `RowNotFound`).
    let codigo = common::codigo_verificacion_dispositivo_encolado(&pool, email).await;

    let resp = cliente
        .post(format!("{base}/auth/verify-device"))
        .json(&json!({ "device_challenge_id": device_challenge_id, "code": codigo }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cuerpo: Value = resp.json().await.unwrap();
    let session_id = cuerpo["session_id"].as_str().unwrap().to_string();

    // --- 1. Con sesión válida NO aplica el límite por IP ---
    // Bug 2026-10-17: listar un vault de 139 claves (~141 pedidos) desde la
    // misma IP que la app de escritorio daba 429.
    for i in 0..280 {
        let resp = cliente
            .get(format!("{base}/resources"))
            .bearer_auth(&session_id)
            .send()
            .await
            .unwrap();
        assert_ne!(resp.status(), 429, "pedido {i} con sesión válida cortado: el límite por IP no debería aplicarse");
    }

    // --- 2. El límite por usuario sigue existiendo (20/s, ráfaga 300) ---
    let mut vio_429 = false;
    for _ in 0..400 {
        let resp = cliente
            .get(format!("{base}/resources"))
            .bearer_auth(&session_id)
            .send()
            .await
            .unwrap();
        if resp.status() == 429 {
            let cuerpo: Value = resp.json().await.expect("el 429 es el JSON de error de la API, no texto plano");
            assert_eq!(cuerpo["error"]["code"], "RATE_LIMITED");
            vio_429 = true;
            break;
        }
    }
    assert!(vio_429, "500 solicitudes rápidas del mismo usuario deberían disparar el límite por usuario");

    // --- 3. Un token inventado no saltea el límite por IP ---
    // Si bastara con mandar cualquier `Authorization`, el límite que frena
    // fuerza bruta en el login dejaría de servir.
    let mut vio_429_ip = false;
    for _ in 0..300 {
        let resp = cliente
            .get(format!("{base}/resources"))
            .bearer_auth(uuid::Uuid::now_v7().to_string())
            .send()
            .await
            .unwrap();
        if resp.status() == 429 {
            vio_429_ip = true;
            break;
        }
    }
    assert!(vio_429_ip, "300 pedidos con tokens inventados desde la misma IP deberían disparar el límite por IP (ráfaga 250)");
}
