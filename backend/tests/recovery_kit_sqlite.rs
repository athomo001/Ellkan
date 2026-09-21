// Autor: Athan Espinoza

//! Segunda implementación (SQLite, modo escritorio) de
//! `RecoveryKitRepository`/`ResetTokenRepository` — mismos casos que
//! `tests/recovery_kit.rs` ejercita indirectamente vía HTTP contra Postgres,
//! acá a nivel de repositorio directo contra `sqlite::memory:` (sin Docker,
//! spec/13 §4). Sólo compila/corre con `--features desktop`.
#![cfg(feature = "desktop")]

use ellkan_backend::desktop::repositories::recovery_kit::{SqliteRecoveryKitRepository, SqliteResetTokenRepository};
use ellkan_backend::recovery_kit::repository::{RecoveryKitRepository, ResetTokenRepository};
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;
use time::OffsetDateTime;
use uuid::Uuid;

async fn pool_de_prueba() -> SqlitePool {
    let pool = SqlitePoolOptions::new().connect("sqlite::memory:").await.expect("conectar sqlite en memoria");
    sqlx::migrate!("../app-escritorio/backend-desktop/migrations_sqlite").run(&pool).await.expect("correr migraciones sqlite");
    pool
}

#[tokio::test]
async fn bootstrap_sqlite_crea_el_archivo_y_corre_migraciones() {
    let datadir = std::env::temp_dir().join(format!("ellkan-test-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&datadir).unwrap();

    let pool = ellkan_backend::desktop::bootstrap_sqlite(&datadir).await.expect("bootstrap_sqlite no debería fallar");
    assert!(datadir.join("ellkan.db").exists(), "bootstrap_sqlite debe crear el archivo de la bóveda");

    // Migraciones ya corridas: la tabla existe y acepta un insert real.
    let repo = SqliteRecoveryKitRepository { pool };
    let kit = repo.upsert(Uuid::now_v7(), b"clave-publica", b"material-sellado").await.unwrap();
    assert!(!kit.must_rotate);

    drop(repo);
    std::fs::remove_dir_all(&datadir).ok();
}

#[tokio::test]
async fn upsert_inserta_y_luego_actualiza_conservando_el_id() {
    let pool = pool_de_prueba().await;
    let repo = SqliteRecoveryKitRepository { pool };
    let user_id = Uuid::now_v7();

    let kit_1 = repo.upsert(user_id, b"clave-publica-v1", b"material-v1").await.unwrap();
    assert_eq!(kit_1.user_id, user_id);
    assert!(!kit_1.must_rotate);

    // Marcar para rotar y luego regenerar (upsert de nuevo) debe limpiar la
    // marca — mismo contrato que la implementación Postgres.
    repo.marcar_para_rotar(user_id).await.unwrap();
    let kit_marcado = repo.buscar_por_usuario(user_id).await.unwrap().expect("debe existir");
    assert!(kit_marcado.must_rotate);

    let kit_2 = repo.upsert(user_id, b"clave-publica-v2", b"material-v2").await.unwrap();
    assert_eq!(kit_2.id, kit_1.id, "regenerar conserva el id de la fila existente, no crea una nueva");
    assert_eq!(kit_2.kit_public_key_x25519, b"clave-publica-v2");
    assert!(!kit_2.must_rotate, "regenerar limpia la marca de rotación");
}

#[tokio::test]
async fn buscar_por_usuario_sin_kit_da_none() {
    let pool = pool_de_prueba().await;
    let repo = SqliteRecoveryKitRepository { pool };
    assert!(repo.buscar_por_usuario(Uuid::now_v7()).await.unwrap().is_none());
}

#[tokio::test]
async fn ciclo_completo_de_reset_token_con_doble_consumo() {
    let pool = pool_de_prueba().await;
    let repo = SqliteResetTokenRepository { pool };
    let user_id = Uuid::now_v7();
    let token_hash = b"hash-del-token-de-prueba".to_vec();
    let vence = OffsetDateTime::now_utc() + time::Duration::minutes(30);

    let id = repo.crear(user_id, &token_hash, vence).await.unwrap();

    let encontrado =
        repo.buscar_vigente_por_hash(&token_hash).await.unwrap().expect("el token recién creado debe estar vigente");
    assert_eq!(encontrado.id, id);
    assert_eq!(encontrado.user_id, user_id);
    assert!(encontrado.consumed_at.is_none());

    let encontrado_por_id = repo.buscar_vigente(id).await.unwrap().expect("buscar_vigente por id también debe encontrarlo");
    assert_eq!(encontrado_por_id.id, id);

    // Primer consumo: éxito.
    assert!(repo.marcar_consumido(id).await.unwrap(), "el primer marcar_consumido debe devolver true");
    // Segundo consumo del mismo token: el lock optimista (`where consumed_at
    // is null`) debe rechazarlo — mismo contrato que la implementación Postgres.
    assert!(!repo.marcar_consumido(id).await.unwrap(), "un token ya consumido no puede volver a consumirse");

    // Ya consumido: ninguna búsqueda "vigente" debe encontrarlo más.
    assert!(repo.buscar_vigente_por_hash(&token_hash).await.unwrap().is_none());
    assert!(repo.buscar_vigente(id).await.unwrap().is_none());
}

#[tokio::test]
async fn token_vencido_no_se_considera_vigente() {
    let pool = pool_de_prueba().await;
    let repo = SqliteResetTokenRepository { pool };
    let token_hash = b"hash-de-un-token-vencido".to_vec();
    let ya_vencio = OffsetDateTime::now_utc() - time::Duration::minutes(1);

    let id = repo.crear(Uuid::now_v7(), &token_hash, ya_vencio).await.unwrap();

    assert!(repo.buscar_vigente_por_hash(&token_hash).await.unwrap().is_none(), "un token vencido no es vigente");
    assert!(repo.buscar_vigente(id).await.unwrap().is_none());
}

#[tokio::test]
async fn guardar_codigo_email_se_puede_leer_de_vuelta() {
    let pool = pool_de_prueba().await;
    let repo = SqliteResetTokenRepository { pool };
    let token_hash = b"hash-con-fallback-de-email".to_vec();
    let vence = OffsetDateTime::now_utc() + time::Duration::minutes(30);
    let id = repo.crear(Uuid::now_v7(), &token_hash, vence).await.unwrap();

    let code_hash = b"hash-del-codigo-de-6-digitos".to_vec();
    let code_vence = OffsetDateTime::now_utc() + time::Duration::minutes(10);
    repo.guardar_codigo_email(id, &code_hash, code_vence).await.unwrap();

    let fila = repo.buscar_vigente(id).await.unwrap().expect("debe seguir vigente");
    assert_eq!(fila.email_code_hash, Some(code_hash));
    assert!(fila.email_code_expires_at.is_some());
}
