// Autor: Athan Espinoza

//! `PUT /resources/{id}` (editar) y `DELETE /resources/{id}` (eliminar) en
//! modo escritorio — faltaban por completo del router (`desktop/router.rs`)
//! hasta 2026-09-16: cualquier intento de editar o borrar un recurso real
//! devolvía 404 (bug encontrado probando en la ventana real). Este test
//! ejercita `ResourceService::editar`/`eliminar` con los repos SQLite
//! reales, mismo patrón que `folders_tags_sqlite.rs`. Sólo compila/corre
//! con `--features desktop`.
#![cfg(feature = "desktop")]

use ellkan_backend::desktop::repositories::admin::SqliteRoleRepository;
use ellkan_backend::desktop::repositories::folders::SqliteFolderItemRepository;
use ellkan_backend::desktop::repositories::groups::SqliteGroupMemberRepository;
use ellkan_backend::desktop::repositories::resources::{
    SqlitePermissionRepository, SqliteResourceRepository, SqliteResourceTypeRepository, SqliteSecretEnvelopeRepository,
};
use ellkan_backend::error::DomainError;
use ellkan_backend::eventos;
use ellkan_backend::resources::models::EnvelopeInput;
use ellkan_backend::resources::repository::{ResourceRepository, ResourceTypeRepository};
use ellkan_backend::resources::service::ResourceService;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;
use uuid::Uuid;

async fn pool_de_prueba() -> SqlitePool {
    let pool = SqlitePoolOptions::new().connect("sqlite::memory:").await.expect("conectar sqlite en memoria");
    sqlx::migrate!("../app-escritorio/backend-desktop/migrations_sqlite").run(&pool).await.expect("correr migraciones sqlite");
    pool
}

struct Repos {
    recursos: SqliteResourceRepository,
    envolturas: SqliteSecretEnvelopeRepository,
    permisos: SqlitePermissionRepository,
    tipos_recurso: SqliteResourceTypeRepository,
    items: SqliteFolderItemRepository,
    grupos: SqliteGroupMemberRepository,
    roles: SqliteRoleRepository,
}

impl Repos {
    fn nuevos(pool: &SqlitePool) -> Self {
        Self {
            recursos: SqliteResourceRepository { pool: pool.clone() },
            envolturas: SqliteSecretEnvelopeRepository { pool: pool.clone() },
            permisos: SqlitePermissionRepository { pool: pool.clone() },
            tipos_recurso: SqliteResourceTypeRepository { pool: pool.clone() },
            items: SqliteFolderItemRepository { pool: pool.clone() },
            grupos: SqliteGroupMemberRepository,
            roles: SqliteRoleRepository,
        }
    }

    #[allow(clippy::type_complexity)]
    fn servicio(
        &self,
    ) -> ResourceService<
        '_,
        SqliteResourceRepository,
        SqliteSecretEnvelopeRepository,
        SqlitePermissionRepository,
        SqliteResourceTypeRepository,
        SqliteFolderItemRepository,
        SqliteGroupMemberRepository,
        SqliteRoleRepository,
    > {
        ResourceService {
            recursos: &self.recursos,
            envolturas: &self.envolturas,
            permisos: &self.permisos,
            tipos_recurso: &self.tipos_recurso,
            items: &self.items,
            grupos: &self.grupos,
            roles: &self.roles,
            eventos: eventos::nuevo_canal(),
        }
    }
}

#[tokio::test]
async fn editar_recurso_re_sella_metadata_y_secreto() {
    let pool = pool_de_prueba().await;
    let repos = Repos::nuevos(&pool);
    let servicio = repos.servicio();
    let user_id = Uuid::now_v7();

    let recurso = repos
        .recursos
        .crear(Uuid::now_v7(), Uuid::now_v7(), b"metadata-v1", b"nonce-v1", user_id, None)
        .await
        .expect("crear recurso de prueba");

    let envelope = EnvelopeInput { user_id, sealed_dek: b"dek-v2".to_vec(), secret_ciphertext: b"secreto-v2".to_vec(), secret_nonce: b"nonce-secreto-v2".to_vec() };

    let editado = servicio
        .editar(recurso.id, user_id, recurso.updated_at, b"metadata-v2", b"nonce-v2", vec![envelope])
        .await
        .expect("editar debe funcionar para el dueño del recurso");

    assert_eq!(editado.metadata_ciphertext, b"metadata-v2");
    assert!(editado.updated_at > recurso.updated_at, "editar debe avanzar el updated_at (concurrencia optimista)");

    // Reintentar con el `updated_at` VIEJO (el que ya quedó obsoleto tras el
    // edit anterior) debe rechazarse — mismo contrato que la versión Postgres.
    let reintento = servicio.editar(recurso.id, user_id, recurso.updated_at, b"metadata-v3", b"nonce-v3", vec![]).await;
    assert!(matches!(reintento, Err(DomainError::Conflict)), "editar con un If-Match desactualizado debe devolver conflicto");
}

#[tokio::test]
async fn eliminar_recurso_lo_saca_del_listado() {
    let pool = pool_de_prueba().await;
    let repos = Repos::nuevos(&pool);
    let servicio = repos.servicio();
    let user_id = Uuid::now_v7();

    let recurso = repos.recursos.crear(Uuid::now_v7(), Uuid::now_v7(), b"m", b"n", user_id, None).await.unwrap();

    servicio.eliminar(recurso.id, user_id).await.expect("eliminar debe funcionar para el dueño del recurso");

    let visibles = servicio.listar_visibles(user_id).await.unwrap();
    assert!(visibles.is_empty(), "un recurso eliminado no debe aparecer más en el listado");

    // Bug real que motivó este archivo: antes de agregar la ruta al router
    // no había forma de llegar hasta acá — el Service en sí ya funcionaba,
    // sólo faltaba el `DELETE /resources/{id}` en `desktop/router.rs`.
    //
    // `PermissionDenied`, no `NotFound`: `ResourceService::obtener` chequea
    // permiso ANTES de buscar el recurso (`tiene_permiso` ya filtra
    // `deleted_at is null`), mismo comportamiento que la versión Postgres
    // — anti-enumeración, no distingue "no existe" de "ya no es tuyo".
    let obtener_borrado = servicio.obtener(recurso.id, user_id).await;
    assert!(matches!(obtener_borrado, Err(DomainError::PermissionDenied)));
}

/// 2026-09-17: `ResourceService::cambiar_tipo` en modo escritorio (mismo
/// código que el server, sólo cambia el repo inyectado) — recursos
/// ssh/ftp/etc. creados como `login-password` genérico ahora se pueden
/// re-tipear entre tipos con el mismo `json_schema`.
#[tokio::test]
async fn cambiar_tipo_entre_compatibles_funciona_y_rechaza_incompatibles() {
    let pool = pool_de_prueba().await;
    let repos = Repos::nuevos(&pool);
    let servicio = repos.servicio();
    let user_id = Uuid::now_v7();

    let id_login_password = repos.tipos_recurso.id_por_slug("login-password").await.unwrap().expect("seed de migración");
    let id_totp = repos.tipos_recurso.id_por_slug("login-password-totp").await.unwrap().expect("seed de migración");

    let recurso = repos.recursos.crear(Uuid::now_v7(), id_login_password, b"m", b"n", user_id, None).await.unwrap();

    let cambiado = servicio.cambiar_tipo(recurso.id, user_id, "ssh").await.expect("login-password -> ssh es compatible");
    let id_ssh = repos.tipos_recurso.id_por_slug("ssh").await.unwrap().unwrap();
    assert_eq!(cambiado.resource_type_id, id_ssh);
    assert_eq!(cambiado.metadata_ciphertext, b"m", "el contenido no debe tocarse al cambiar sólo el tipo");

    let rechazado = servicio.cambiar_tipo(recurso.id, user_id, "login-password-totp").await;
    assert!(
        matches!(rechazado, Err(DomainError::ValidacionInvalida(_))),
        "ssh -> login-password-totp tiene json_schema distinto, debe rechazarse"
    );

    // Confirma que el rechazo no aplicó nada — sigue siendo `ssh`, no `totp`.
    let sigue_ssh = repos.recursos.buscar(recurso.id).await.unwrap().unwrap();
    assert_eq!(sigue_ssh.resource_type_id, id_ssh);
    let _ = id_totp; // documenta que el id existe/se resolvió, aunque el cambio se haya rechazado
}
