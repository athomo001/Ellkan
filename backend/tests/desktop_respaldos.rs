// Autor: Athan Espinoza

//! F-53: `ellkan.db` es la única copia de los datos del usuario. Antes de
//! aplicar migraciones pendientes la app guarda una copia, y el usuario puede
//! pedir otra cuando quiera. Sólo compila y corre con `--features desktop`.
#![cfg(feature = "desktop")]

use std::path::PathBuf;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use ellkan_backend::auth::repository::SessionRepository;
use ellkan_backend::desktop::respaldos::{
    carpeta_de_respaldos, listar, respaldar, version_previa_si_hay_pendientes, PREFIJO_AUTOMATICO, PREFIJO_MANUAL, RETENCION,
};
use ellkan_backend::desktop::router::construir_router_desktop;
use ellkan_backend::desktop::state::AppStateDesktop;
use ellkan_backend::desktop::bootstrap_sqlite;
use secrecy::SecretBox;
use serde_json::Value;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use tower::ServiceExt;
use uuid::Uuid;

fn datadir_temporal(nombre: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ellkan_test_respaldos_{nombre}_{}", Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

async fn pool_migrado_en_memoria() -> SqlitePool {
    let pool = SqlitePoolOptions::new().connect("sqlite::memory:").await.unwrap();
    sqlx::migrate!("../app-escritorio/backend-desktop/migrations_sqlite").run(&pool).await.unwrap();
    pool
}

async fn abrir(dir: &std::path::Path, archivo: &str) -> SqlitePool {
    SqlitePoolOptions::new()
        .connect_with(SqliteConnectOptions::new().filename(dir.join(archivo)).create_if_missing(false))
        .await
        .unwrap()
}

#[tokio::test]
async fn una_base_nueva_no_necesita_copia() {
    let pool = SqlitePoolOptions::new().connect("sqlite::memory:").await.unwrap();
    let migrador = sqlx::migrate!("../app-escritorio/backend-desktop/migrations_sqlite");
    assert_eq!(version_previa_si_hay_pendientes(&pool, &migrador).await.unwrap(), None, "no hay nada que proteger en una base vacía");
}

#[tokio::test]
async fn una_base_al_dia_no_necesita_copia() {
    let pool = pool_migrado_en_memoria().await;
    let migrador = sqlx::migrate!("../app-escritorio/backend-desktop/migrations_sqlite");
    assert_eq!(version_previa_si_hay_pendientes(&pool, &migrador).await.unwrap(), None);
}

#[tokio::test]
async fn con_una_migracion_pendiente_se_detecta_desde_que_version_se_parte() {
    let pool = pool_migrado_en_memoria().await;
    let migrador = sqlx::migrate!("../app-escritorio/backend-desktop/migrations_sqlite");
    let ultima: i64 = sqlx::query_scalar("select max(version) from _sqlx_migrations").fetch_one(&pool).await.unwrap();
    // Como una base que quedó una versión atrás: la última migración no está aplicada.
    sqlx::query("delete from _sqlx_migrations where version = ?1").bind(ultima).execute(&pool).await.unwrap();

    let anterior: i64 = sqlx::query_scalar("select max(version) from _sqlx_migrations").fetch_one(&pool).await.unwrap();
    assert_eq!(version_previa_si_hay_pendientes(&pool, &migrador).await.unwrap(), Some(anterior));
}

#[tokio::test]
async fn la_copia_es_una_base_completa_con_los_mismos_datos() {
    let dir = datadir_temporal("copia");
    let pool = bootstrap_sqlite(&dir).await.unwrap();
    sqlx::query("insert into server_keys (id, public_key_ed25519, private_key_ed25519) values (1, x'0102', x'0304')")
        .execute(&pool)
        .await
        .unwrap();

    let copia = respaldar(&pool, &dir, PREFIJO_MANUAL, "").await.expect("respaldar");

    assert!(copia.starts_with(carpeta_de_respaldos(&dir)));
    let nombre = copia.file_name().unwrap().to_str().unwrap().to_string();
    assert!(nombre.starts_with(PREFIJO_MANUAL) && nombre.ends_with(".db"), "{nombre}");
    let respaldo = abrir(&carpeta_de_respaldos(&dir), &nombre).await;
    let claves: i64 = sqlx::query_scalar("select count(*) from server_keys").fetch_one(&respaldo).await.unwrap();
    assert_eq!(claves, 1, "la copia trae los datos de la bóveda");
    let migraciones: i64 = sqlx::query_scalar("select count(*) from _sqlx_migrations").fetch_one(&respaldo).await.unwrap();
    assert!(migraciones > 0, "y su esquema, para poder restaurarla");
}

#[tokio::test]
async fn se_conservan_solo_las_ultimas_copias_de_cada_tipo() {
    let dir = datadir_temporal("retencion");
    let pool = bootstrap_sqlite(&dir).await.unwrap();

    let mut manuales = Vec::new();
    for _ in 0..(RETENCION + 3) {
        manuales.push(respaldar(&pool, &dir, PREFIJO_MANUAL, "").await.unwrap());
        std::thread::sleep(std::time::Duration::from_millis(3)); // el nombre lleva milisegundos
    }
    respaldar(&pool, &dir, PREFIJO_AUTOMATICO, "v0001-").await.unwrap();

    let existentes = listar(&dir).unwrap();
    assert_eq!(existentes.iter().filter(|r| !r.automatico).count(), RETENCION, "sólo las {RETENCION} manuales más nuevas");
    assert_eq!(existentes.iter().filter(|r| r.automatico).count(), 1, "podar un tipo no toca al otro");
    assert!(!manuales[0].exists(), "la más vieja se borró");
    assert!(manuales.last().unwrap().exists(), "la más nueva sigue");
}

#[tokio::test]
async fn arrancar_con_migraciones_pendientes_guarda_una_copia_y_migra() {
    let dir = datadir_temporal("arranque");

    // Primer arranque: base nueva, sin copia.
    let pool = bootstrap_sqlite(&dir).await.unwrap();
    assert!(listar(&dir).unwrap().is_empty(), "una base nueva no genera copia");
    let ultima: i64 = sqlx::query_scalar("select max(version) from _sqlx_migrations").fetch_one(&pool).await.unwrap();

    // Se simula una app vieja: las migraciones 7 (`metadata_deks`) y 8 (tipos rdp/db)
    // no se habían aplicado — se deshace lo que hicieron y se borra su registro.
    sqlx::query("drop table metadata_deks").execute(&pool).await.unwrap();
    sqlx::query("delete from resource_types where slug in ('rdp', 'postgresql', 'mysql', 'mongodb')").execute(&pool).await.unwrap();
    sqlx::query("delete from _sqlx_migrations where version >= 7").execute(&pool).await.unwrap();
    assert!(ultima >= 7, "el test parte de una base con las migraciones 7 y siguientes aplicadas");
    pool.close().await;

    // Segundo arranque, ya con la app nueva: hay una migración pendiente.
    let pool = bootstrap_sqlite(&dir).await.unwrap();
    let copias = listar(&dir).unwrap();
    assert_eq!(copias.len(), 1, "antes de migrar se guardó una copia");
    assert!(copias[0].automatico);
    assert!(copias[0].nombre.contains("v0006"), "la copia dice desde qué versión se partió: {}", copias[0].nombre);

    // Y la migración se aplicó: la tabla nueva existe otra vez.
    let existe: i64 = sqlx::query_scalar("select count(*) from sqlite_master where name = 'metadata_deks'").fetch_one(&pool).await.unwrap();
    assert_eq!(existe, 1);

    // La copia es la base ANTES de migrar: no tiene la tabla.
    let copia = abrir(&carpeta_de_respaldos(&dir), &copias[0].nombre).await;
    let en_copia: i64 = sqlx::query_scalar("select count(*) from sqlite_master where name = 'metadata_deks'").fetch_one(&copia).await.unwrap();
    assert_eq!(en_copia, 0, "la copia conserva el estado previo a la migración");

    // Tercer arranque: ya está al día, no hay copia nueva.
    pool.close().await;
    let _ = bootstrap_sqlite(&dir).await.unwrap();
    assert_eq!(listar(&dir).unwrap().len(), 1);
}

fn estado(pool: &SqlitePool, dir: PathBuf) -> AppStateDesktop {
    let secrets_key: SecretBox<[u8; 32]> = SecretBox::new(Box::new([0u8; 32]));
    AppStateDesktop::nuevo(dir, pool.clone(), [9u8; 32], secrets_key)
}

#[tokio::test]
async fn las_rutas_de_copias_exigen_sesion_y_crean_y_listan() {
    let dir = datadir_temporal("rutas");
    let pool = bootstrap_sqlite(&dir).await.unwrap();

    // Sin sesión: 401.
    let resp = construir_router_desktop(estado(&pool, dir.clone()))
        .oneshot(Request::builder().method("GET").uri("/vault/backups").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Con sesión: crea y lista.
    sqlx::query(
        "insert into users (id, email, display_name, security_stamp, email_verified_at)
         values ('01a0a85d-3be1-70f1-b692-e270dd61fcf3', 'yo@local.ellkan', 'Yo', '01a0a85d-3be1-70f1-b692-e270dd61fcf4', '2026-01-01T00:00:00.000Z')",
    )
    .execute(&pool)
    .await
    .unwrap();
    let user_id = Uuid::parse_str("01a0a85d-3be1-70f1-b692-e270dd61fcf3").unwrap();
    let sesion = estado(&pool, dir.clone())
        .sesiones
        .crear(user_id, Uuid::parse_str("01a0a85d-3be1-70f1-b692-e270dd61fcf4").unwrap())
        .await
        .unwrap();

    let llamar = |metodo: &'static str| {
        let pool = pool.clone();
        let dir = dir.clone();
        async move {
            let resp = construir_router_desktop(estado(&pool, dir))
                .oneshot(
                    Request::builder()
                        .method(metodo)
                        .uri("/vault/backups")
                        .header("authorization", format!("Bearer {}", sesion.id))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let cuerpo: Value = serde_json::from_slice(&to_bytes(resp.into_body(), usize::MAX).await.unwrap()).unwrap();
            (status, cuerpo)
        }
    };

    let (status, cuerpo) = llamar("GET").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(cuerpo["respaldos"].as_array().unwrap().len(), 0);
    assert!(cuerpo["carpeta"].as_str().unwrap().ends_with("backups"));

    let (status, cuerpo) = llamar("POST").await;
    assert_eq!(status, StatusCode::OK);
    let lista = cuerpo["respaldos"].as_array().unwrap();
    assert_eq!(lista.len(), 1);
    assert_eq!(lista[0]["automatico"], false);
    assert!(lista[0]["bytes"].as_u64().unwrap() > 0);
    assert!(carpeta_de_respaldos(&dir).join(lista[0]["nombre"].as_str().unwrap()).exists());
}
