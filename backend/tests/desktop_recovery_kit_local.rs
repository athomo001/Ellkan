// Autor: Athan Espinoza

//! Punto 8 (recuperación local sin SMTP): las rutas del recovery kit no
//! estaban montadas en el router de escritorio y el reset por correo no puede
//! funcionar sin SMTP. Acá se ejercita el camino nuevo por HTTP en memoria,
//! con firmas Ed25519 reales: el reset se autoriza demostrando que se tiene
//! la clave de la cuenta (que sólo se obtiene abriendo el kit), no con un
//! correo.
#![cfg(feature = "desktop")]

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use ellkan_backend::auth::repository::SessionRepository;
use ellkan_backend::desktop::router::construir_router_desktop;
use ellkan_backend::desktop::state::AppStateDesktop;
use secrecy::SecretBox;
use serde_json::{json, Value};
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;
use tower::ServiceExt;
use uuid::Uuid;

const EMAIL: &str = "yo@local.ellkan";

async fn pool_de_prueba() -> SqlitePool {
    let pool = SqlitePoolOptions::new().connect("sqlite::memory:").await.expect("conectar sqlite en memoria");
    sqlx::migrate!("../app-escritorio/backend-desktop/migrations_sqlite").run(&pool).await.expect("correr migraciones sqlite");
    pool
}

fn estado(pool: &SqlitePool) -> AppStateDesktop {
    let datadir = std::env::temp_dir().join(format!("ellkan_test_recovery_local_{}", Uuid::now_v7()));
    let secrets_key: SecretBox<[u8; 32]> = SecretBox::new(Box::new([0u8; 32]));
    AppStateDesktop::nuevo(datadir, pool.clone(), [9u8; 32], secrets_key)
}

async fn llamar(pool: &SqlitePool, metodo: &str, uri: &str, bearer: Option<Uuid>, cuerpo: Value) -> (StatusCode, Value) {
    let mut req = Request::builder().method(metodo).uri(uri).header("content-type", "application/json");
    if let Some(sesion) = bearer {
        req = req.header("authorization", format!("Bearer {sesion}"));
    }
    let resp = construir_router_desktop(estado(pool)).oneshot(req.body(Body::from(cuerpo.to_string())).unwrap()).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let cuerpo: Value = if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap() };
    (status, cuerpo)
}

/// Clave de la cuenta: la que en la vida real se obtiene abriendo el kit.
fn clave_de_cuenta() -> SigningKey {
    SigningKey::from_bytes(&[42u8; 32])
}

/// Registra al único usuario con la clave pública Ed25519 de `clave` y le
/// abre una sesión completa. Devuelve `(user_id, session_id)`.
async fn usuario_con_sesion(pool: &SqlitePool, clave: &SigningKey) -> (Uuid, Uuid) {
    let registro = json!({
        "email": EMAIL,
        "display_name": "Usuario de prueba",
        "public_key_x25519_b64": B64.encode([1u8; 32]),
        "public_key_ed25519_b64": B64.encode(clave.verifying_key().to_bytes()),
        "encrypted_private_key_blob_b64": B64.encode([3u8; 48]),
        "private_key_nonce_b64": B64.encode([4u8; 24]),
        "kdf_salt_b64": B64.encode([5u8; 16]),
    });
    let (status, _) = llamar(pool, "POST", "/auth/register", None, registro).await;
    assert_eq!(status, StatusCode::OK, "el registro inicial debe funcionar");

    let fila: (String, String) = sqlx::query_as("select id, security_stamp from users where email = ?1")
        .bind(EMAIL)
        .fetch_one(pool)
        .await
        .unwrap();
    let user_id = Uuid::parse_str(&fila.0).unwrap();
    let sesion = estado(pool).sesiones.crear(user_id, Uuid::parse_str(&fila.1).unwrap()).await.expect("crear sesión");
    (user_id, sesion.id)
}

fn cuerpo_kit() -> Value {
    json!({
        "kit_public_key_x25519_b64": B64.encode([11u8; 32]),
        "sealed_identity_material_b64": B64.encode([12u8; 112]),
    })
}

/// Pide un challenge por la ruta pública de siempre y devuelve el nonce.
async fn pedir_nonce(pool: &SqlitePool) -> Vec<u8> {
    let (status, cuerpo) = llamar(pool, "POST", "/auth/challenge", None, json!({ "email": EMAIL })).await;
    assert_eq!(status, StatusCode::OK);
    B64.decode(cuerpo["nonce_b64"].as_str().expect("nonce_b64")).unwrap()
}

fn cuerpo_recuperar(nonce: &[u8], firma: &[u8]) -> Value {
    json!({
        "email": EMAIL,
        "nonce_b64": B64.encode(nonce),
        "signature_b64": B64.encode(firma),
        "encrypted_private_key_blob_b64": B64.encode([21u8; 48]),
        "private_key_nonce_b64": B64.encode([22u8; 24]),
        "kdf_salt_b64": B64.encode([23u8; 16]),
    })
}

async fn blob_actual(pool: &SqlitePool, user_id: Uuid) -> Vec<u8> {
    sqlx::query_scalar("select encrypted_private_key_blob from user_keys where user_id = ?1")
        .bind(user_id.to_string())
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn el_kit_se_puede_generar_y_su_estado_se_ve_sin_exponer_el_contenido() {
    let pool = pool_de_prueba().await;
    let (_user, sesion) = usuario_con_sesion(&pool, &clave_de_cuenta()).await;

    let (status, cuerpo) = llamar(&pool, "GET", "/me/recovery-kit", Some(sesion), Value::Null).await;
    assert_eq!(status, StatusCode::OK, "antes del punto 8 esto daba 404 en escritorio");
    assert_eq!(cuerpo["configured"], false);

    let (status, _) = llamar(&pool, "PUT", "/me/recovery-kit", Some(sesion), cuerpo_kit()).await;
    assert_eq!(status, StatusCode::OK);

    let (_, cuerpo) = llamar(&pool, "GET", "/me/recovery-kit", Some(sesion), Value::Null).await;
    assert_eq!(cuerpo["configured"], true);
    assert_eq!(cuerpo["must_rotate"], false);
    assert!(cuerpo.get("sealed_identity_material_b64").is_none(), "el estado nunca devuelve el contenido del kit");
}

#[tokio::test]
async fn generar_el_kit_rechaza_una_clave_publica_que_no_mide_32_bytes() {
    let pool = pool_de_prueba().await;
    let (_user, sesion) = usuario_con_sesion(&pool, &clave_de_cuenta()).await;

    let mut cuerpo = cuerpo_kit();
    cuerpo["kit_public_key_x25519_b64"] = json!(B64.encode([11u8; 31]));
    let (status, _) = llamar(&pool, "PUT", "/me/recovery-kit", Some(sesion), cuerpo).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = llamar(&pool, "PUT", "/me/recovery-kit", None, cuerpo_kit()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "sin sesión no se puede registrar un kit");
}

#[tokio::test]
async fn el_material_sellado_se_entrega_sin_sesion_solo_si_hay_kit() {
    let pool = pool_de_prueba().await;
    let (_user, sesion) = usuario_con_sesion(&pool, &clave_de_cuenta()).await;

    let (status, _) = llamar(&pool, "POST", "/auth/recovery-kit/local/material", None, json!({ "email": EMAIL })).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "sin kit configurado no hay material");

    llamar(&pool, "PUT", "/me/recovery-kit", Some(sesion), cuerpo_kit()).await;
    let (status, cuerpo) = llamar(&pool, "POST", "/auth/recovery-kit/local/material", None, json!({ "email": EMAIL })).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(cuerpo["sealed_identity_material_b64"], B64.encode([12u8; 112]));

    let (status, _) = llamar(&pool, "POST", "/auth/recovery-kit/local/material", None, json!({ "email": "otro@x.com" })).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn reset_con_firma_valida_reemplaza_el_blob_mata_las_sesiones_y_marca_el_kit_para_rotar() {
    let pool = pool_de_prueba().await;
    let clave = clave_de_cuenta();
    let (user_id, sesion) = usuario_con_sesion(&pool, &clave).await;
    llamar(&pool, "PUT", "/me/recovery-kit", Some(sesion), cuerpo_kit()).await;

    let nonce = pedir_nonce(&pool).await;
    let firma = clave.sign(&nonce).to_bytes();
    let (status, _) = llamar(&pool, "POST", "/auth/recovery-kit/local/complete", None, cuerpo_recuperar(&nonce, &firma)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(blob_actual(&pool, user_id).await, vec![21u8; 48], "el blob re-sellado con la passphrase nueva debe quedar guardado");

    let (status, _) = llamar(&pool, "GET", "/me/recovery-kit", Some(sesion), Value::Null).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "la sesión abierta antes del reset debe morir (security_stamp rotado)");

    // El kit usado queda obsoleto — se verifica por la base, la sesión vieja ya no sirve.
    let must_rotate: bool = sqlx::query_scalar("select must_rotate from recovery_kits where user_id = ?1")
        .bind(user_id.to_string())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(must_rotate, "después de un reset el próximo login tiene que forzar un kit nuevo");
}

#[tokio::test]
async fn reset_rechaza_una_firma_de_otra_clave_sin_tocar_nada() {
    let pool = pool_de_prueba().await;
    let (user_id, sesion) = usuario_con_sesion(&pool, &clave_de_cuenta()).await;
    llamar(&pool, "PUT", "/me/recovery-kit", Some(sesion), cuerpo_kit()).await;

    let intruso = SigningKey::from_bytes(&[99u8; 32]);
    let nonce = pedir_nonce(&pool).await;
    let firma = intruso.sign(&nonce).to_bytes();
    let (status, _) = llamar(&pool, "POST", "/auth/recovery-kit/local/complete", None, cuerpo_recuperar(&nonce, &firma)).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(blob_actual(&pool, user_id).await, vec![3u8; 48], "una firma inválida no debe cambiar el blob");
    let (status, _) = llamar(&pool, "GET", "/me/recovery-kit", Some(sesion), Value::Null).await;
    assert_eq!(status, StatusCode::OK, "ni matar la sesión");
}

#[tokio::test]
async fn el_challenge_es_de_un_solo_uso_no_se_puede_repetir_un_reset() {
    let pool = pool_de_prueba().await;
    let clave = clave_de_cuenta();
    let (_user, sesion) = usuario_con_sesion(&pool, &clave).await;
    llamar(&pool, "PUT", "/me/recovery-kit", Some(sesion), cuerpo_kit()).await;

    let nonce = pedir_nonce(&pool).await;
    let firma = clave.sign(&nonce).to_bytes();
    let (primero, _) = llamar(&pool, "POST", "/auth/recovery-kit/local/complete", None, cuerpo_recuperar(&nonce, &firma)).await;
    let (repetido, _) = llamar(&pool, "POST", "/auth/recovery-kit/local/complete", None, cuerpo_recuperar(&nonce, &firma)).await;

    assert_eq!(primero, StatusCode::OK);
    assert_eq!(repetido, StatusCode::UNAUTHORIZED, "reusar el mismo challenge firmado debe rechazarse");
}

#[tokio::test]
async fn reset_sin_kit_configurado_se_rechaza_aunque_la_firma_sea_valida() {
    let pool = pool_de_prueba().await;
    let clave = clave_de_cuenta();
    let (user_id, _sesion) = usuario_con_sesion(&pool, &clave).await;

    let nonce = pedir_nonce(&pool).await;
    let firma = clave.sign(&nonce).to_bytes();
    let (status, _) = llamar(&pool, "POST", "/auth/recovery-kit/local/complete", None, cuerpo_recuperar(&nonce, &firma)).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(blob_actual(&pool, user_id).await, vec![3u8; 48]);
}

#[tokio::test]
async fn reset_con_un_blob_invalido_se_rechaza_sin_gastar_el_estado_de_la_cuenta() {
    let pool = pool_de_prueba().await;
    let clave = clave_de_cuenta();
    let (user_id, sesion) = usuario_con_sesion(&pool, &clave).await;
    llamar(&pool, "PUT", "/me/recovery-kit", Some(sesion), cuerpo_kit()).await;

    let nonce = pedir_nonce(&pool).await;
    let firma = clave.sign(&nonce).to_bytes();
    let mut cuerpo = cuerpo_recuperar(&nonce, &firma);
    cuerpo["private_key_nonce_b64"] = json!(B64.encode([22u8; 12])); // XChaCha20 usa 24
    let (status, _) = llamar(&pool, "POST", "/auth/recovery-kit/local/complete", None, cuerpo).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(blob_actual(&pool, user_id).await, vec![3u8; 48]);
    let (status, _) = llamar(&pool, "GET", "/me/recovery-kit", Some(sesion), Value::Null).await;
    assert_eq!(status, StatusCode::OK, "un pedido inválido no debe rotar el security_stamp");
}
