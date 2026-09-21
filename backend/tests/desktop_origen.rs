// Autor: Athan Espinoza

//! El backend local sólo escucha en loopback, pero cualquier página web
//! abierta en el navegador del usuario puede llamarlo (y con DNS rebinding
//! hasta parecer "mismo origen"). Estos tests fijan quién puede hablarle:
//! sólo la app, las extensiones de navegador y (en debug) el servidor de Vite;
//! y el `Host` tiene que ser loopback. Además: cerrar sesión ahora revoca la
//! sesión en el backend local en vez de sólo olvidar el token en el cliente.
#![cfg(feature = "desktop")]

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ellkan_backend::auth::repository::SessionRepository;
use ellkan_backend::desktop::origen::{host_permitido, origen_permitido};
use ellkan_backend::desktop::router::construir_router_desktop;
use ellkan_backend::desktop::state::AppStateDesktop;
use secrecy::SecretBox;
use serde_json::{json, Value};
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;
use tower::ServiceExt;
use uuid::Uuid;

async fn pool_de_prueba() -> SqlitePool {
    let pool = SqlitePoolOptions::new().connect("sqlite::memory:").await.expect("conectar sqlite en memoria");
    sqlx::migrate!("../app-escritorio/backend-desktop/migrations_sqlite").run(&pool).await.expect("correr migraciones sqlite");
    pool
}

fn estado(pool: &SqlitePool) -> AppStateDesktop {
    let datadir = std::env::temp_dir().join(format!("ellkan_test_origen_{}", Uuid::now_v7()));
    let secrets_key: SecretBox<[u8; 32]> = SecretBox::new(Box::new([0u8; 32]));
    AppStateDesktop::nuevo(datadir, pool.clone(), [9u8; 32], secrets_key)
}

/// Llama a `uri` con las cabeceras dadas y devuelve el status y la cabecera
/// `access-control-allow-origin` de la respuesta.
async fn llamar(pool: &SqlitePool, metodo: &str, uri: &str, cabeceras: &[(&str, &str)]) -> (StatusCode, Option<String>) {
    let mut req = Request::builder().method(metodo).uri(uri);
    for (nombre, valor) in cabeceras {
        req = req.header(*nombre, *valor);
    }
    let resp = construir_router_desktop(estado(pool)).oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
    let acao = resp.headers().get("access-control-allow-origin").map(|v| v.to_str().unwrap().to_string());
    let status = resp.status();
    let _ = to_bytes(resp.into_body(), usize::MAX).await;
    (status, acao)
}

#[test]
fn los_origenes_de_la_app_y_de_las_extensiones_se_permiten() {
    for permitido in [
        "http://tauri.localhost",
        "https://tauri.localhost",
        "tauri://localhost",
        "chrome-extension://abcdefghijklmnopabcdefghijklmnop",
        "moz-extension://5b6c1f9e-2a3d-4e8f-9c0b-1a2b3c4d5e6f",
        "safari-web-extension://ABCDEF12-3456",
    ] {
        assert!(origen_permitido(permitido), "{permitido} debería poder llamar al backend local");
    }
}

#[test]
fn una_pagina_web_cualquiera_no_puede_llamar_al_backend_local() {
    for rechazado in [
        "https://evil.example",
        "http://evil.example",
        "http://127.0.0.1:5173.evil.example",
        "http://localhost:8080",
        "http://127.0.0.1:54416",
        "http://tauri.localhost.evil.example",
        "null",
        "file://",
        "",
        "chrome-extension://",
        "chrome-extension://../etc",
        "chrome-extension://abc/def",
    ] {
        assert!(!origen_permitido(rechazado), "{rechazado:?} NO debería poder llamar al backend local");
    }
}

#[test]
fn el_servidor_de_vite_solo_se_permite_en_debug() {
    assert_eq!(origen_permitido("http://localhost:5173"), cfg!(debug_assertions));
    assert_eq!(origen_permitido("http://127.0.0.1:5173"), cfg!(debug_assertions));
}

#[test]
fn el_host_tiene_que_ser_loopback() {
    for bueno in ["127.0.0.1", "127.0.0.1:54416", "localhost", "localhost:54416", "LOCALHOST:1", "[::1]", "[::1]:54416"] {
        assert!(host_permitido(bueno), "{bueno} es loopback");
    }
    for malo in ["evil.example", "evil.example:54416", "127.0.0.1.evil.example", "127.0.0.1.evil.example:80", "10.0.0.5:54416", "[::2]:1", ""] {
        assert!(!host_permitido(malo), "{malo:?} no es loopback (DNS rebinding)");
    }
}

#[tokio::test]
async fn sin_origen_ni_host_se_atiende_como_siempre() {
    // El helper de SSH, `curl` y estas mismas pruebas no mandan `Origin`.
    let pool = pool_de_prueba().await;
    let (status, _) = llamar(&pool, "GET", "/auth/existe-usuario", &[]).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn la_app_y_las_extensiones_reciben_el_cors_de_su_origen() {
    let pool = pool_de_prueba().await;
    for origen in ["http://tauri.localhost", "chrome-extension://abcdefghijklmnopabcdefghijklmnop"] {
        let (status, acao) = llamar(&pool, "GET", "/auth/existe-usuario", &[("host", "127.0.0.1:54416"), ("origin", origen)]).await;
        assert_eq!(status, StatusCode::OK, "{origen}");
        assert_eq!(acao.as_deref(), Some(origen), "el CORS tiene que devolver el origen permitido, no `*`");
    }
}

#[tokio::test]
async fn una_pagina_ajena_recibe_403_y_nunca_ve_la_respuesta() {
    let pool = pool_de_prueba().await;
    for origen in ["https://evil.example", "null", "http://localhost:8080"] {
        let (status, acao) = llamar(&pool, "GET", "/auth/existe-usuario", &[("host", "127.0.0.1:54416"), ("origin", origen)]).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{origen}");
        assert_eq!(acao, None, "un origen ajeno no debe recibir cabeceras CORS");
    }
}

#[tokio::test]
async fn el_preflight_de_una_pagina_ajena_tambien_se_corta() {
    let pool = pool_de_prueba().await;
    let (status, acao) = llamar(
        &pool,
        "OPTIONS",
        "/auth/challenge",
        &[("host", "127.0.0.1:54416"), ("origin", "https://evil.example"), ("access-control-request-method", "POST")],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(acao, None);
}

#[tokio::test]
async fn el_preflight_de_la_app_se_responde() {
    let pool = pool_de_prueba().await;
    let (status, acao) = llamar(
        &pool,
        "OPTIONS",
        "/auth/challenge",
        &[
            ("host", "127.0.0.1:54416"),
            ("origin", "http://tauri.localhost"),
            ("access-control-request-method", "POST"),
            ("access-control-request-headers", "authorization,content-type"),
        ],
    )
    .await;
    assert!(status.is_success(), "el preflight de la app tiene que responderse, fue {status}");
    assert_eq!(acao.as_deref(), Some("http://tauri.localhost"));
}

#[tokio::test]
async fn un_host_ajeno_se_rechaza_aunque_no_haya_origen_dns_rebinding() {
    // DNS rebinding: la página del atacante resuelve su dominio a 127.0.0.1,
    // así que para el navegador es "mismo origen" y ni siquiera manda `Origin`
    // en un GET — lo único que delata el ataque es el `Host`.
    let pool = pool_de_prueba().await;
    let (status, _) = llamar(&pool, "GET", "/auth/existe-usuario", &[("host", "evil.example:54416")]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// Registra al único usuario y le abre una sesión. Devuelve `(user_id, session_id)`.
async fn usuario_con_sesion(pool: &SqlitePool) -> (Uuid, Uuid) {
    let registro = json!({
        "email": "yo@local.ellkan",
        "display_name": "Usuario de prueba",
        "public_key_x25519_b64": B64.encode([1u8; 32]),
        "public_key_ed25519_b64": B64.encode([2u8; 32]),
        "encrypted_private_key_blob_b64": B64.encode([3u8; 48]),
        "private_key_nonce_b64": B64.encode([4u8; 24]),
        "kdf_salt_b64": B64.encode([5u8; 16]),
    });
    let resp = construir_router_desktop(estado(pool))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/register")
                .header("content-type", "application/json")
                .body(Body::from(registro.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let fila: (String, String) = sqlx::query_as("select id, security_stamp from users where email = 'yo@local.ellkan'")
        .fetch_one(pool)
        .await
        .unwrap();
    let user_id = Uuid::parse_str(&fila.0).unwrap();
    let sesion = estado(pool).sesiones.crear(user_id, Uuid::parse_str(&fila.1).unwrap()).await.expect("crear sesión");
    (user_id, sesion.id)
}

async fn con_sesion(pool: &SqlitePool, metodo: &str, uri: &str, sesion: Uuid) -> StatusCode {
    let resp = construir_router_desktop(estado(pool))
        .oneshot(
            Request::builder()
                .method(metodo)
                .uri(uri)
                .header("authorization", format!("Bearer {sesion}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    resp.status()
}

#[tokio::test]
async fn cerrar_sesion_revoca_la_sesion_en_el_backend_local() {
    let pool = pool_de_prueba().await;
    let (_user_id, sesion) = usuario_con_sesion(&pool).await;

    assert_eq!(con_sesion(&pool, "GET", "/me", sesion).await, StatusCode::OK, "la sesión abierta funciona");
    assert_eq!(con_sesion(&pool, "POST", "/auth/logout", sesion).await, StatusCode::OK);
    assert_eq!(
        con_sesion(&pool, "GET", "/me", sesion).await,
        StatusCode::UNAUTHORIZED,
        "tras cerrar sesión el token ya no sirve, aunque alguien lo hubiera copiado"
    );
}

#[tokio::test]
async fn cerrar_sesion_sin_sesion_se_rechaza() {
    let pool = pool_de_prueba().await;
    let resp = construir_router_desktop(estado(&pool))
        .oneshot(Request::builder().method("POST").uri("/auth/logout").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let _: Value = serde_json::from_slice(&bytes).unwrap();
}
