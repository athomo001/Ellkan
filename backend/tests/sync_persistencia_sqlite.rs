// Autor: Athan Espinoza

//! Pruebas de integración de la Fase 3.3 (F-48 y F-47): Modos de persistencia
//! y sincronización diferencial en SQLite para el modo escritorio.
//! Solo compila y corre con `--features desktop`.
#![cfg(feature = "desktop")]

use std::fs;
use time::OffsetDateTime;
use uuid::Uuid;

use ellkan_backend::desktop::repositories::resources::{SqliteMetadataDekRepository, SqliteResourceRepository, SqliteSecretEnvelopeRepository};
use ellkan_backend::desktop::sqlite_util::fmt_dt;
use ellkan_backend::desktop::{cargar_config, guardar_config, ModoPersistencia};
use ellkan_backend::resources::repository::{ResourceRepository, SecretEnvelopeRepository};
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;

async fn pool_de_prueba() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .expect("conectar sqlite en memoria");
    sqlx::migrate!("../app-escritorio/backend-desktop/migrations_sqlite")
        .run(&pool)
        .await
        .expect("correr migraciones sqlite");
    pool
}

#[tokio::test]
async fn test_persistencia_modos_configuracion() {
    let dir = std::env::temp_dir().join(format!("ellkan_test_sync_{}", Uuid::now_v7()));
    fs::create_dir_all(&dir).expect("crear dir temporal");
    let datadir = dir.as_path();

    // 1. Configuración por defecto debe ser ModoPersistencia::Full
    let config_inicial = cargar_config(datadir).expect("cargar config inicial");
    assert_eq!(config_inicial.modo_persistencia, ModoPersistencia::Full);

    // 2. Modificación a ModoPersistencia::Memory
    let mut config_modificada = config_inicial.clone();
    config_modificada.modo_persistencia = ModoPersistencia::Memory;
    guardar_config(datadir, &config_modificada).expect("guardar config memory");

    let recargada = cargar_config(datadir).expect("recargar config");
    assert_eq!(recargada.modo_persistencia, ModoPersistencia::Memory);

    // 3. Modificación a ModoPersistencia::NamesOnly
    config_modificada.modo_persistencia = ModoPersistencia::NamesOnly;
    guardar_config(datadir, &config_modificada).expect("guardar config names_only");

    let recargada_names = cargar_config(datadir).expect("recargar config names_only");
    assert_eq!(recargada_names.modo_persistencia, ModoPersistencia::NamesOnly);
    let _ = fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_sincronizacion_diferencial_deltas() {
    let pool = pool_de_prueba().await;
    let repo = SqliteResourceRepository { pool: pool.clone() };

    let user_id = Uuid::now_v7();
    let tipo_id = Uuid::parse_str("019a0000-0000-7000-8000-000000000001").unwrap();

    let t0 = fmt_dt(OffsetDateTime::now_utc());

    // 1. Crear recurso
    let res_id = Uuid::now_v7();
    let recurso = repo
        .crear(res_id, tipo_id, b"meta_cifrada", b"nonce_123456", user_id, None)
        .await
        .expect("crear recurso");

    assert_eq!(recurso.id, res_id);

    // 2. Consultar recursos creados desde t0
    let filas: Vec<String> = sqlx::query_scalar(
        "select id from resources where created_by = ?1 and deleted_at is null and updated_at >= ?2",
    )
    .bind(user_id.to_string())
    .bind(&t0)
    .fetch_all(&pool)
    .await
    .expect("query deltas creados");

    assert_eq!(filas.len(), 1);
    assert_eq!(filas[0], res_id.to_string());

    let _t1 = fmt_dt(OffsetDateTime::now_utc());

    // 3. Eliminar recurso
    let borrado = repo.marcar_eliminado(res_id).await.expect("marcar eliminado");
    assert!(borrado);

    // 4. Consultar eliminados desde t0
    let eliminados: Vec<String> = sqlx::query_scalar(
        "select id from resources where created_by = ?1 and deleted_at is not null and deleted_at >= ?2",
    )
    .bind(user_id.to_string())
    .bind(&t0)
    .fetch_all(&pool)
    .await
    .expect("query deltas eliminados");

    assert_eq!(eliminados.len(), 1);
    assert_eq!(eliminados[0], res_id.to_string());
}

/// F-48 real (2026-09-18, cierre del gap documentado en
/// `spec/05-plan-de-implementacion.md` línea 244): un recurso creado por el
/// camino "sólo metadata" (el que usa `sincronizarAhora()` del frontend en
/// modos `Memory`/`NamesOnly`) nunca debe dejar una fila en
/// `secret_envelopes` — el DEK sellado que sí hace falta para descifrar la
/// metadata offline vive aparte, en `metadata_deks`.
#[tokio::test]
async fn crear_metadata_only_no_persiste_secreto_pero_guarda_el_dek() {
    let pool = pool_de_prueba().await;
    let recursos = SqliteResourceRepository { pool: pool.clone() };
    let envolturas = SqliteSecretEnvelopeRepository { pool: pool.clone() };
    let metadata_deks = SqliteMetadataDekRepository { pool: pool.clone() };

    let user_id = Uuid::now_v7();
    let tipo_id = Uuid::parse_str("019a0000-0000-7000-8000-000000000001").unwrap();
    let res_id = Uuid::now_v7();

    // Mismo camino que usa el handler `crear_recurso_metadata_only`:
    // `ResourceRepository::crear` (genérico, sin secreto) + guardar el DEK
    // aparte — nunca `SecretEnvelopeRepository::insertar`.
    let recurso = recursos.crear(res_id, tipo_id, b"meta-cifrada", b"nonce-meta", user_id, None).await.expect("crear metadata-only");
    metadata_deks.guardar(recurso.id, user_id, b"dek-sellada").await.expect("guardar metadata dek");

    let envelope = envolturas.buscar(res_id, user_id).await.expect("buscar no debe fallar");
    assert!(envelope.is_none(), "un recurso metadata-only no debe tener fila en secret_envelopes");

    let dek = metadata_deks.buscar(res_id, user_id).await.expect("buscar dek no debe fallar");
    assert_eq!(dek.as_deref(), Some(&b"dek-sellada"[..]), "el DEK sellado debe quedar disponible para descifrar metadata offline");
}

/// Misma concurrencia optimista que `ResourceRepository::actualizar` (ver
/// `resources_editar_eliminar_sqlite.rs`), pero para la variante que sólo
/// toca metadata — `actualizar_metadata_solo` nunca debe tocar
/// `secret_envelopes`, ni siquiera cuando la actualización sí aplica.
#[tokio::test]
async fn actualizar_metadata_solo_respeta_concurrencia_optimista_y_no_toca_secretos() {
    let pool = pool_de_prueba().await;
    let recursos = SqliteResourceRepository { pool: pool.clone() };
    let envolturas = SqliteSecretEnvelopeRepository { pool: pool.clone() };

    let user_id = Uuid::now_v7();
    let tipo_id = Uuid::parse_str("019a0000-0000-7000-8000-000000000001").unwrap();
    let recurso = recursos.crear(Uuid::now_v7(), tipo_id, b"meta-v1", b"nonce-v1", user_id, None).await.expect("crear recurso");
    let updated_at_original = recurso.updated_at;

    // `fmt_dt` tiene precisión de milisegundos: sin esta pausa la creación y
    // el update pueden caer en el mismo ms y `updated_at` no avanzaría.
    std::thread::sleep(std::time::Duration::from_millis(5));

    let actualizado = recursos
        .actualizar_metadata_solo(recurso.id, updated_at_original, b"meta-v2", b"nonce-v2")
        .await
        .expect("no debe fallar")
        .expect("el If-Match correcto (el de la creación) debe aplicar la actualización");
    assert_eq!(actualizado.metadata_ciphertext, b"meta-v2");
    assert!(actualizado.updated_at > updated_at_original, "debe avanzar updated_at, misma concurrencia optimista que actualizar()");

    let sigue_sin_secreto = envolturas.buscar(recurso.id, user_id).await.expect("buscar no debe fallar");
    assert!(sigue_sin_secreto.is_none(), "actualizar_metadata_solo nunca debe crear una fila en secret_envelopes");

    // Reintentar con el `updated_at` ORIGINAL (ya obsoleto tras el update de
    // arriba) debe rechazarse — mismo contrato que `actualizar()`.
    let reintento = recursos.actualizar_metadata_solo(recurso.id, updated_at_original, b"meta-v3", b"nonce-v3").await.expect("no debe fallar");
    assert!(reintento.is_none(), "un If-Match desactualizado debe devolver None");

    let sigue_v2 = recursos.buscar(recurso.id).await.expect("buscar no debe fallar").expect("debe existir");
    assert_eq!(sigue_v2.metadata_ciphertext, b"meta-v2", "el reintento rechazado no debe haber aplicado nada");
}
