// Autor: Athan Espinoza

//! `PUT /me/email` (modo escritorio, punto 6 de la lista de pendientes): la
//! cuenta local única nace desconectada y con el correo que el usuario haya
//! tipeado; poder cambiarlo es lo que permite alinearlo después con el de
//! una cuenta del servidor central. Mismo enfoque que
//! `desktop_registro_unico.rs`: se ejercita el router completo por HTTP en
//! memoria, porque lo que hay que probar vive en el handler.
#![cfg(feature = "desktop")]

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ellkan_backend::auth::repository::SessionRepository;
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
    let datadir = std::env::temp_dir().join(format!("ellkan_test_cambiar_email_{}", Uuid::now_v7()));
    let secrets_key: SecretBox<[u8; 32]> = SecretBox::new(Box::new([0u8; 32]));
    AppStateDesktop::nuevo(datadir, pool.clone(), [9u8; 32], secrets_key)
}

async fn llamar(estado: AppStateDesktop, metodo: &str, uri: &str, bearer: Option<Uuid>, cuerpo: Value) -> (StatusCode, Value) {
    let mut req = Request::builder().method(metodo).uri(uri).header("content-type", "application/json");
    if let Some(sesion) = bearer {
        req = req.header("authorization", format!("Bearer {sesion}"));
    }
    let resp = construir_router_desktop(estado).oneshot(req.body(Body::from(cuerpo.to_string())).unwrap()).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let cuerpo: Value = if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap() };
    (status, cuerpo)
}

/// Registra el único usuario local por HTTP y le abre una sesión completa
/// directo contra el repositorio (el login real exige cripto de cliente que
/// acá no hace falta ejercitar). Devuelve `(user_id, session_id)`.
async fn usuario_con_sesion(pool: &SqlitePool, email: &str) -> (Uuid, Uuid) {
    let registro = json!({
        "email": email,
        "display_name": "Usuario de prueba",
        "public_key_x25519_b64": B64.encode([1u8; 32]),
        "public_key_ed25519_b64": B64.encode([2u8; 32]),
        "encrypted_private_key_blob_b64": B64.encode([3u8; 48]),
        "private_key_nonce_b64": B64.encode([4u8; 24]),
        "kdf_salt_b64": B64.encode([5u8; 16]),
    });
    let (status, _) = llamar(estado(pool), "POST", "/auth/register", None, registro).await;
    assert_eq!(status, StatusCode::OK, "el registro inicial debe funcionar");

    let fila: (String, String) = sqlx::query_as("select id, security_stamp from users where email = ?1")
        .bind(email)
        .fetch_one(pool)
        .await
        .expect("el usuario recién registrado debe existir");
    let user_id = Uuid::parse_str(&fila.0).unwrap();
    let stamp = Uuid::parse_str(&fila.1).unwrap();

    let sesion = estado(pool).sesiones.crear(user_id, stamp).await.expect("crear sesión de prueba");
    (user_id, sesion.id)
}

async fn email_actual(pool: &SqlitePool, user_id: Uuid) -> String {
    sqlx::query_scalar("select email from users where id = ?1").bind(user_id.to_string()).fetch_one(pool).await.unwrap()
}

async fn blob_actual(pool: &SqlitePool, user_id: Uuid) -> Vec<u8> {
    sqlx::query_scalar("select encrypted_private_key_blob from user_keys where user_id = ?1")
        .bind(user_id.to_string())
        .fetch_one(pool)
        .await
        .unwrap()
}

/// Cuerpo de `PUT /me/email` — el blob ya re-sellado con el correo nuevo
/// (bytes distintos de los del registro, para poder distinguir que se aplicó).
fn cuerpo_cambio(email: &str) -> Value {
    json!({
        "new_email": email,
        "encrypted_private_key_blob_b64": B64.encode([7u8; 48]),
        "private_key_nonce_b64": B64.encode([8u8; 24]),
        "kdf_salt_b64": B64.encode([9u8; 16]),
    })
}

#[tokio::test]
async fn cambiar_email_actualiza_correo_y_blob_juntos_y_devuelve_el_correo_recortado() {
    let pool = pool_de_prueba().await;
    let (user_id, sesion) = usuario_con_sesion(&pool, "viejo@local.ellkan").await;

    let (status, cuerpo) = llamar(estado(&pool), "PUT", "/me/email", Some(sesion), cuerpo_cambio("  nuevo@empresa.com  ")).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(cuerpo["email"], "nuevo@empresa.com", "debe devolver el correo ya recortado");
    assert_eq!(email_actual(&pool, user_id).await, "nuevo@empresa.com");
    assert_eq!(blob_actual(&pool, user_id).await, vec![7u8; 48], "el blob re-sellado debe aplicarse junto con el correo — sin él la cuenta no se podría desbloquear");
}

#[tokio::test]
async fn cambiar_email_rechaza_una_forma_invalida_sin_tocar_nada() {
    let pool = pool_de_prueba().await;
    let (user_id, sesion) = usuario_con_sesion(&pool, "viejo@local.ellkan").await;

    for invalido in ["sin-arroba", "@sin-local.com", "sin-dominio@", "dos@@arrobas.com", "con espacio@x.com", ""] {
        let (status, _) = llamar(estado(&pool), "PUT", "/me/email", Some(sesion), cuerpo_cambio(invalido)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{invalido:?} debe rechazarse");
    }
    assert_eq!(email_actual(&pool, user_id).await, "viejo@local.ellkan", "ningún intento inválido debe haber aplicado nada");
    assert_eq!(blob_actual(&pool, user_id).await, vec![3u8; 48], "ni el blob");
}

#[tokio::test]
async fn cambiar_email_rechaza_un_blob_invalido_sin_cambiar_el_correo() {
    let pool = pool_de_prueba().await;
    let (user_id, sesion) = usuario_con_sesion(&pool, "viejo@local.ellkan").await;

    // Nonce de longitud incorrecta (XChaCha20 usa 24 bytes).
    let mut cuerpo = cuerpo_cambio("nuevo@empresa.com");
    cuerpo["private_key_nonce_b64"] = json!(B64.encode([8u8; 12]));
    let (status, _) = llamar(estado(&pool), "PUT", "/me/email", Some(sesion), cuerpo).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(email_actual(&pool, user_id).await, "viejo@local.ellkan", "un blob inválido no debe dejar el correo cambiado con la clave vieja");
}

#[tokio::test]
async fn cambiar_email_exige_sesion() {
    let pool = pool_de_prueba().await;
    let (user_id, _sesion) = usuario_con_sesion(&pool, "viejo@local.ellkan").await;

    let (status, _) = llamar(estado(&pool), "PUT", "/me/email", None, cuerpo_cambio("nuevo@empresa.com")).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(email_actual(&pool, user_id).await, "viejo@local.ellkan");
}

#[tokio::test]
async fn cambiar_email_a_uno_ya_usado_por_otro_usuario_se_rechaza_y_no_toca_el_blob() {
    let pool = pool_de_prueba().await;
    let (user_id, sesion) = usuario_con_sesion(&pool, "viejo@local.ellkan").await;

    // El modo escritorio no permite un segundo usuario por la API — se inserta
    // directo sólo para forzar la colisión de `unique(email)`.
    sqlx::query("insert into users (id, email, display_name, security_stamp) values (?1, 'ocupado@empresa.com', 'Otro', ?2)")
        .bind(Uuid::now_v7().to_string())
        .bind(Uuid::now_v7().to_string())
        .execute(&pool)
        .await
        .expect("insertar el usuario que ocupa el correo");

    let (status, cuerpo) = llamar(estado(&pool), "PUT", "/me/email", Some(sesion), cuerpo_cambio("ocupado@empresa.com")).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(cuerpo["error"]["message"].as_str().unwrap_or_default().contains("ya está en uso"));
    assert_eq!(email_actual(&pool, user_id).await, "viejo@local.ellkan");
    assert_eq!(blob_actual(&pool, user_id).await, vec![3u8; 48], "el rechazo no debe dejar el blob a medias");
}
