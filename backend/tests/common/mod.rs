// Autor: Athan Espinoza

//! Helpers compartidos entre los tests de integración de Fase 1.1 — Postgres
//! real vía `testcontainers` (nunca mockeado), mismo criterio ya usado en
//! `flujo_completo.rs` de Fase 0. Se extrae acá porque a partir de esta fase
//! son más de tres archivos de test los que necesitan "levantar servidor +
//! registrar + loguear" para llegar al escenario real que cada uno cubre.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::Signer;
use ellkan_crypto::claves::{KeypairAcuerdo, KeypairFirma};
use ellkan_crypto::clave_privada;
use ellkan_crypto::secretos::PassphraseSecreta;
use secrecy::SecretBox;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt};
use uuid::Uuid;

pub struct Entorno {
    pub base: String,
    pub pool: sqlx::PgPool,
    pub cliente: reqwest::Client,
    // Nunca se lee directo — mantiene el contenedor vivo mientras el test
    // corre (`testcontainers` lo detiene al hacer `drop`).
    _contenedor: ContainerAsync<Postgres>,
}

pub async fn levantar() -> Entorno {
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

    let estado = ellkan_backend::construir_estado(&database_url).await.expect("migrar y conectar");
    let pool = estado.pool.clone();
    let app = ellkan_backend::construir_router(estado);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await
            .unwrap();
    });

    Entorno {
        base: format!("http://{addr}"),
        pool,
        cliente: reqwest::Client::new(),
        _contenedor: contenedor,
    }
}

// Helper compartido: no todos los binarios de test usan todos los campos
// (ej. `admin_roles.rs` no hace criptografía de recursos) — cada binario de
// integración compila `common/mod.rs` de cero, así que el warning de
// dead-code es por-consumidor, no señal real de código muerto.
#[allow(dead_code)]
pub struct Usuario {
    pub email: String,
    pub user_id: Uuid,
    pub x25519: KeypairAcuerdo,
    pub ed25519: KeypairFirma,
    pub passphrase: PassphraseSecreta,
    pub device_token: [u8; 32],
}

pub async fn registrar(entorno: &Entorno, email: &str) -> Usuario {
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
    let status = resp.status();
    let texto = resp.text().await.unwrap();
    assert_eq!(status, 200, "register debería devolver 200, body: {texto}");
    let cuerpo: Value = serde_json::from_str(&texto).unwrap();
    let user_id: Uuid = cuerpo["user_id"].as_str().unwrap().parse().unwrap();

    let device_token: [u8; 32] = ellkan_crypto::aleatoriedad::bytes_aleatorios();
    Usuario { email: email.to_string(), user_id, x25519, ed25519, passphrase, device_token }
}

/// El consumidor de eventos que encola el email corre en su propia tarea
/// tokio, desacoplado a propósito del request HTTP que lo dispara — bajo
/// carga (muchos tests con Postgres en paralelo) puede no haber escrito la
/// fila todavía en el instante exacto en que el test la busca, así que se
/// reintenta brevemente en vez de fallar al primer miss.
async fn codigo_de_verificacion_encolado(pool: &sqlx::PgPool, email: &str) -> String {
    let mut ultimo_error = None;
    for _ in 0..20 {
        match sqlx::query_as::<_, (String,)>(
            "select body from outbound_emails where recipient = $1 order by created_at desc limit 1",
        )
        .bind(email)
        .fetch_one(pool)
        .await
        {
            Ok(fila) => return extraer_codigo(&fila.0),
            Err(e) => {
                ultimo_error = Some(e);
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
    panic!("debería haber un email encolado para este usuario tras reintentar: {ultimo_error:?}");
}

fn extraer_codigo(cuerpo: &str) -> String {
    cuerpo
        .lines()
        .find_map(|linea| linea.strip_prefix("Código de verificación: "))
        .expect("el cuerpo del email debería contener el código")
        .trim()
        .to_string()
}

/// Login completo: primer login desde un `device_token` nuevo siempre queda
/// `pendiente_dispositivo` — el helper "lee el email" (stub, F-02) y cierra
/// con `verify-device`, igual que haría un cliente real.
pub async fn login(entorno: &Entorno, usuario: &Usuario) -> Uuid {
    let resp = entorno
        .cliente
        .post(format!("{}/auth/challenge", entorno.base))
        .json(&json!({ "email": usuario.email }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
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
    assert_eq!(resp.status(), 200, "verify debería aceptar una firma válida");
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(
        cuerpo["estado"], "pendiente_dispositivo",
        "primer login desde un device_token nunca visto debe quedar pendiente"
    );
    let device_challenge_id = cuerpo["device_challenge_id"].as_str().unwrap();

    let codigo = codigo_de_verificacion_encolado(&entorno.pool, &usuario.email).await;

    let resp = entorno
        .cliente
        .post(format!("{}/auth/verify-device", entorno.base))
        .json(&json!({ "device_challenge_id": device_challenge_id, "code": codigo }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let texto = resp.text().await.unwrap();
    assert_eq!(status, 200, "verify-device debería aceptar el código correcto, body: {texto}");
    let cuerpo: Value = serde_json::from_str(&texto).unwrap();
    cuerpo["session_id"].as_str().unwrap().parse().unwrap()
}

/// Promueve a un usuario a rol `admin` directo por SQL — equivalente de test
/// a `ellkan-cli admin promote-to-admin` (F-41), sin pasar por HTTP: ningún
/// endpoint de la API permite auto-promoverse, a propósito.
#[allow(dead_code)]
pub async fn promover_admin(pool: &sqlx::PgPool, user_id: Uuid) {
    sqlx::query("update users set role_id = (select id from roles where name = 'admin') where id = $1")
        .bind(user_id)
        .execute(pool)
        .await
        .expect("promover a admin en el test");
}
