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
    post(estado, "/auth/register", cuerpo_registro(email)).await
}

async fn post(estado: AppStateDesktop, uri: &str, cuerpo: Value) -> (StatusCode, Value) {
    let router = construir_router_desktop(estado);
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(cuerpo.to_string()))
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

/// F-47: conectar la app a una cuenta que ya existe en un servidor. El
/// usuario local tiene que nacer con el MISMO id que en el servidor (el
/// cifrado de cada recurso usa el id de su creador), y con la misma regla de
/// un solo usuario por bóveda.
#[tokio::test]
async fn registro_desde_servidor_conserva_el_id_y_respeta_el_usuario_unico() {
    let pool = pool_de_prueba().await;
    let datadir = std::env::temp_dir().join(format!("ellkan_test_registro_servidor_{}", uuid::Uuid::now_v7()));
    let id_del_servidor = uuid::Uuid::now_v7();
    let mut cuerpo = cuerpo_registro("yo@servidor.ellkan");
    cuerpo["user_id"] = json!(id_del_servidor);

    let estado = || AppStateDesktop::nuevo(datadir.clone(), pool.clone(), [9u8; 32], SecretBox::new(Box::new([0u8; 32])));
    let (status, respuesta) = post(estado(), "/auth/register-desde-servidor", cuerpo.clone()).await;
    assert_eq!(status, StatusCode::OK, "{respuesta}");
    assert_eq!(respuesta["user_id"], json!(id_del_servidor), "el usuario local debe tener el id del servidor");
    assert_eq!(respuesta["pending_verification"], json!(false));

    let guardado: String = sqlx::query_scalar("select id from users").fetch_one(&pool).await.unwrap();
    assert_eq!(guardado, id_del_servidor.to_string());

    // Ni por esta vía ni por el registro normal se puede crear un segundo usuario.
    let (status2, _) = post(estado(), "/auth/register-desde-servidor", cuerpo).await;
    assert_eq!(status2, StatusCode::BAD_REQUEST);
    let (status3, _) = registrar(estado(), "otro@local.ellkan").await;
    assert_eq!(status3, StatusCode::BAD_REQUEST);
}

/// F-47 parte B: unir una bóveda local existente con la cuenta del servidor.
/// Exige sesión local, reemplaza la identidad (id del servidor) y borra los
/// datos ligados a la identidad vieja en la misma operación.
#[tokio::test]
async fn adoptar_identidad_exige_sesion_y_reemplaza_al_usuario_local() {
    let pool = pool_de_prueba().await;
    let datadir = std::env::temp_dir().join(format!("ellkan_test_adoptar_{}", uuid::Uuid::now_v7()));
    let estado = || AppStateDesktop::nuevo(datadir.clone(), pool.clone(), [9u8; 32], SecretBox::new(Box::new([0u8; 32])));

    let (status, local) = registrar(estado(), "es@la.cl").await;
    assert_eq!(status, StatusCode::OK);
    let id_local: uuid::Uuid = serde_json::from_value(local["user_id"].clone()).unwrap();
    let stamp: String = sqlx::query_scalar("select security_stamp from users").fetch_one(&pool).await.unwrap();
    let sesion = uuid::Uuid::now_v7();
    sqlx::query("insert into sessions (id, user_id, security_stamp, mfa_verified_at, expires_at) values (?1, ?2, ?3, ?4, ?5)")
        .bind(sesion.to_string())
        .bind(id_local.to_string())
        .bind(stamp)
        .bind(ellkan_backend::desktop::sqlite_util::fmt_dt(time::OffsetDateTime::now_utc()))
        .bind(ellkan_backend::desktop::sqlite_util::fmt_dt(time::OffsetDateTime::now_utc() + time::Duration::hours(1)))
        .execute(&pool)
        .await
        .expect("sesión de prueba (si cambió el esquema de `sessions`, ajustar este insert)");

    let id_servidor = uuid::Uuid::now_v7();
    let mut cuerpo = cuerpo_registro("es@la.cl");
    cuerpo["user_id"] = json!(id_servidor);

    // Sin sesión, rechazado.
    let (sin_sesion, _) = post(estado(), "/auth/adoptar-identidad", cuerpo.clone()).await;
    assert_eq!(sin_sesion, StatusCode::UNAUTHORIZED);

    let router = construir_router_desktop(estado());
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/adoptar-identidad")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {sesion}"))
                .body(Body::from(cuerpo.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let ids: Vec<String> = sqlx::query_scalar("select id from users").fetch_all(&pool).await.unwrap();
    assert_eq!(ids, vec![id_servidor.to_string()], "queda un único usuario, con el id del servidor");
    let sesiones: i64 = sqlx::query_scalar("select count(*) from sessions").fetch_one(&pool).await.unwrap();
    assert_eq!(sesiones, 0, "la sesión de la identidad vieja no sobrevive");
}
