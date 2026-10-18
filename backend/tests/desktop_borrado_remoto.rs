// Autor: Athan Espinoza

//! Revocación remota, lado escritorio (docs/revocacion-remota.md): con el
//! aviso firmado ya verificado por el frontend, `POST /desktop/borrado-remoto`
//! corta el acceso y borra la bóveda en el acto, con la base abierta. Y si
//! algo quedó a medias, el arranque siguiente lo completa (`ejecutar`). Sólo
//! compila y corre con `--features desktop`.
#![cfg(feature = "desktop")]

use std::path::PathBuf;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ellkan_backend::auth::repository::SessionRepository;
use ellkan_backend::desktop::borrado_remoto::{ejecutar, marcar, pendiente, MARCA};
use ellkan_backend::desktop::bootstrap_sqlite;
use ellkan_backend::desktop::router::construir_router_desktop;
use ellkan_backend::desktop::state::AppStateDesktop;
use secrecy::SecretBox;
use tower::ServiceExt;
use uuid::Uuid;

fn datadir_temporal(nombre: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ellkan_test_borrado_{nombre}_{}", Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn ejecutar_borra_todo_y_por_ultimo_la_marca() {
    let dir = datadir_temporal("ejecutar");
    std::fs::write(dir.join("ellkan.db"), b"base").unwrap();
    std::fs::write(dir.join("ellkan.db-wal"), b"wal").unwrap();
    std::fs::write(dir.join("config.json"), b"{}").unwrap();
    std::fs::create_dir_all(dir.join("backups")).unwrap();
    std::fs::write(dir.join("backups").join("copia.db"), b"copia").unwrap();
    marcar(&dir, "https://ellkan.test").unwrap();
    assert!(pendiente(&dir));

    ejecutar(&dir).unwrap();

    assert!(!pendiente(&dir), "completo: la marca se borra al final");
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0, "la carpeta de datos queda vacía, como recién instalada");
}

#[tokio::test]
async fn el_endpoint_corta_el_acceso_y_borra_la_boveda_con_la_base_abierta() {
    let dir = datadir_temporal("endpoint");
    let pool = bootstrap_sqlite(&dir).await.unwrap();
    sqlx::query(
        "insert into users (id, email, display_name, security_stamp, email_verified_at)
         values ('01a0a85d-3be1-70f1-b692-e270dd61fcf3', 'yo@local.ellkan', 'Yo', '01a0a85d-3be1-70f1-b692-e270dd61fcf4', '2026-01-01T00:00:00.000Z')",
    )
    .execute(&pool)
    .await
    .unwrap();
    let estado = AppStateDesktop::nuevo(dir.clone(), pool.clone(), [9u8; 32], SecretBox::new(Box::new([0u8; 32])));
    let sesion = estado
        .sesiones
        .crear(Uuid::parse_str("01a0a85d-3be1-70f1-b692-e270dd61fcf3").unwrap(), Uuid::parse_str("01a0a85d-3be1-70f1-b692-e270dd61fcf4").unwrap())
        .await
        .unwrap();
    let router = construir_router_desktop(estado);
    let pedido = |metodo: &str, uri: &str, cuerpo: &str| {
        Request::builder()
            .method(metodo)
            .uri(uri)
            .header("authorization", format!("Bearer {}", sesion.id))
            .header("content-type", "application/json")
            .body(Body::from(cuerpo.to_string()))
            .unwrap()
    };

    assert_eq!(router.clone().oneshot(pedido("GET", "/me", "")).await.unwrap().status(), StatusCode::OK);

    let resp = router
        .clone()
        .oneshot(pedido("POST", "/desktop/borrado-remoto", r#"{"servidor":"https://ellkan.test"}"#))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    assert!(!dir.join("ellkan.db").exists(), "la bóveda se borra en el acto, con la app abierta");
    assert!(!dir.join(MARCA).exists(), "si se borró todo, no queda nada pendiente para el próximo arranque");

    // Desde ahí el backend local no sirve nada (ni a la ventana ni a la extensión).
    let resp = router.clone().oneshot(pedido("GET", "/me", "")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let resp = router
        .oneshot(Request::builder().method("POST").uri("/auth/challenge").header("content-type", "application/json").body(Body::from(r#"{"email":"yo@local.ellkan"}"#)).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
