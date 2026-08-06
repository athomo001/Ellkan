// Autor: Athan Espinoza

//! Confirma que el rate limiting por `user_id` autenticado es una capa real
//! y no sólo el `GovernorLayer` por IP: mismo usuario, muchas solicitudes
//! rápidas contra una ruta autenticada, se espera un 429 antes de agotar la
//! ráfaga configurada (10/s, ráfaga 20).

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

    // Dispositivo nunca visto -> hay que "leer el email" (stub, ver notificaciones.rs).
    let (body,): (String,) =
        sqlx::query_as("select body from outbound_emails where recipient = $1 order by created_at desc limit 1")
            .bind(email)
            .fetch_one(&pool)
            .await
            .unwrap();
    let codigo = body
        .lines()
        .find_map(|l| l.strip_prefix("Código de verificación: "))
        .unwrap()
        .trim()
        .to_string();

    let resp = cliente
        .post(format!("{base}/auth/verify-device"))
        .json(&json!({ "device_challenge_id": device_challenge_id, "code": codigo }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cuerpo: Value = resp.json().await.unwrap();
    let session_id = cuerpo["session_id"].as_str().unwrap().to_string();

    // --- Ráfaga de GET /resources con la misma sesión (mismo user_id) ---
    let mut vio_429 = false;
    for _ in 0..40 {
        let resp = cliente
            .get(format!("{base}/resources"))
            .bearer_auth(&session_id)
            .send()
            .await
            .unwrap();
        if resp.status() == 429 {
            vio_429 = true;
            break;
        }
    }
    assert!(vio_429, "40 solicitudes rápidas del mismo usuario deberían disparar el límite por usuario (10/s, ráfaga 20)");
}
