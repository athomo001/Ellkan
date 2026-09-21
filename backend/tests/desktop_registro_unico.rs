// Autor: Athan Espinoza

//! F-46 (modo escritorio = 1 solo usuario, pedido explícito del usuario
//! 2026-09-17): `POST /auth/register` debe rechazar un segundo registro
//! explícito, con un mensaje que diga la razón real — no depender del
//! efecto colateral accidental de los stubs de SMTP/self-registration (ver
//! el comentario en `app-escritorio/backend-desktop/router.rs::register`).
//! Único test de este repo que ejercita el router de escritorio completo
//! por HTTP en memoria (`tower::ServiceExt::oneshot`), en vez del Service
//! directo — lo que hay que probar acá vive en el handler, no en el
//! Service.
#![cfg(feature = "desktop")]

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use ellkan_backend::desktop::router::construir_router_desktop;
use ellkan_backend::desktop::state::AppStateDesktop;
use secrecy::SecretBox;
use serde_json::{json, Value};
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;
use tower::ServiceExt;

async fn pool_de_prueba() -> SqlitePool {
    let pool = SqlitePoolOptions::new().connect("sqlite::memory:").await.expect("conectar sqlite en memoria");
    sqlx::migrate!("../app-escritorio/backend-desktop/migrations_sqlite").run(&pool).await.expect("correr migraciones sqlite");
    pool
}

fn cuerpo_registro(email: &str) -> Value {
    // Sólo la LONGITUD de las claves públicas importa en este punto
    // (`AuthService::registrar` valida 32 bytes, nunca que sean puntos
    // válidos de la curva) — 32 bytes cualquiera alcanzan para este test.
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    json!({
        "email": email,
        "display_name": "Usuario de prueba",
        "public_key_x25519_b64": B64.encode([1u8; 32]),
        "public_key_ed25519_b64": B64.encode([2u8; 32]),
        "encrypted_private_key_blob_b64": B64.encode([3u8; 48]),
        "private_key_nonce_b64": B64.encode([4u8; 24]),
        "kdf_salt_b64": B64.encode([5u8; 16]),
    })
}

async fn registrar(estado: AppStateDesktop, email: &str) -> (StatusCode, Value) {
    let router = construir_router_desktop(estado);
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(cuerpo_registro(email).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let cuerpo: Value = if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap() };
    (status, cuerpo)
}

#[tokio::test]
async fn segundo_registro_se_rechaza_explicito_con_el_motivo_real() {
    let pool = pool_de_prueba().await;
    let datadir = std::env::temp_dir().join(format!("ellkan_test_registro_unico_{}", uuid::Uuid::now_v7()));
    let secrets_key: SecretBox<[u8; 32]> = SecretBox::new(Box::new([0u8; 32]));

    let estado1 = AppStateDesktop::nuevo(datadir.clone(), pool.clone(), [9u8; 32], secrets_key);
    let (status1, _cuerpo1) = registrar(estado1, "primero@local.ellkan").await;
    assert_eq!(status1, StatusCode::OK, "el primer registro de una bóveda vacía debe funcionar");

    // Nuevo `AppStateDesktop` (mismo pool SQLite subyacente) — mismo
    // criterio que un segundo request real contra el mismo backend local
    // ya arrancado, sin reusar el primero por accidente.
    let secrets_key2: SecretBox<[u8; 32]> = SecretBox::new(Box::new([0u8; 32]));
    let estado2 = AppStateDesktop::nuevo(datadir, pool, [9u8; 32], secrets_key2);
    let (status2, cuerpo2) = registrar(estado2, "segundo@local.ellkan").await;

    assert_eq!(status2, StatusCode::BAD_REQUEST, "un segundo registro debe rechazarse, modo escritorio es de 1 solo usuario");
    let mensaje = cuerpo2["error"]["message"].as_str().unwrap_or_default();
    assert!(
        mensaje.contains("un solo usuario") || mensaje.contains("ya tiene un usuario"),
        "el mensaje debe explicar la razón real (1 solo usuario), no el efecto colateral de SMTP/self-registration: {mensaje:?}"
    );
}
