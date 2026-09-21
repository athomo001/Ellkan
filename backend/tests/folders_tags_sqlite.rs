// Autor: Athan Espinoza

//! Segunda implementación (SQLite, modo escritorio) de
//! `FolderRepository`/`FolderItemRepository`/`TagRepository` — ejercitadas a
//! través de `FolderService`/`TagService` (no sólo el repository a secas),
//! porque el bug real que motivó esta reparación (2026-09-16, ver
//! spec/10-mapa-mental.md "Fase 3.1 en curso") estaba en
//! `SqliteRoleRepository::usuario_tiene_permiso` (antes siempre `false`):
//! `FolderService::es_privilegiado` nunca daba `true` con 1 solo usuario sin
//! roles/grupos, así que anidar una carpeta (`parent_folder_id` distinto de
//! `None`) siempre devolvía `PermissionDenied` — un test sólo contra el
//! repository no lo hubiera detectado. Sólo compila/corre con `--features
//! desktop`.
#![cfg(feature = "desktop")]

use ellkan_backend::desktop::repositories::admin::SqliteRoleRepository;
use ellkan_backend::desktop::repositories::folders::{SqliteFolderItemRepository, SqliteFolderRepository};
use ellkan_backend::desktop::repositories::groups::SqliteGroupMemberRepository;
use ellkan_backend::desktop::repositories::resources::{SqlitePermissionRepository, SqliteResourceRepository};
use ellkan_backend::desktop::repositories::tags::SqliteTagRepository;
use ellkan_backend::error::DomainError;
use ellkan_backend::folders::repository::FolderItemRepository;
use ellkan_backend::folders::service::FolderService;
use ellkan_backend::resources::repository::ResourceRepository;
use ellkan_backend::tags::service::TagService;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;
use uuid::Uuid;

async fn pool_de_prueba() -> SqlitePool {
    let pool = SqlitePoolOptions::new().connect("sqlite::memory:").await.expect("conectar sqlite en memoria");
    sqlx::migrate!("../app-escritorio/backend-desktop/migrations_sqlite").run(&pool).await.expect("correr migraciones sqlite");
    pool
}

/// Repos con los que se arma `FolderService` en cada test — bindings
/// nombrados (no temporales inline) para que las referencias que
/// `FolderService` guarda tengan un dueño explícito y vivan tanto como el
/// `servicio` que las toma prestadas.
struct ReposDeCarpetas {
    carpetas: SqliteFolderRepository,
    items: SqliteFolderItemRepository,
    permisos: SqlitePermissionRepository,
    grupos: SqliteGroupMemberRepository,
    roles: SqliteRoleRepository,
}

impl ReposDeCarpetas {
    fn nuevos(pool: &SqlitePool) -> Self {
        Self {
            carpetas: SqliteFolderRepository { pool: pool.clone() },
            items: SqliteFolderItemRepository { pool: pool.clone() },
            permisos: SqlitePermissionRepository { pool: pool.clone() },
            grupos: SqliteGroupMemberRepository,
            roles: SqliteRoleRepository,
        }
    }

    fn servicio(&self) -> FolderService<'_, SqliteFolderRepository, SqliteFolderItemRepository, SqlitePermissionRepository, SqliteGroupMemberRepository, SqliteRoleRepository> {
        FolderService { carpetas: &self.carpetas, items: &self.items, permisos: &self.permisos, grupos: &self.grupos, roles: &self.roles }
    }
}

#[tokio::test]
async fn anidar_una_subcarpeta_funciona_con_un_solo_usuario_local() {
    let pool = pool_de_prueba().await;
    let repos = ReposDeCarpetas::nuevos(&pool);
    let servicio = repos.servicio();
    let user_id = Uuid::now_v7();

    let raiz = servicio.crear(user_id, Uuid::now_v7(), b"raiz-cifrada", b"nonce", None).await.unwrap();

    // Bug real arreglado 2026-09-16: antes de corregir
    // `SqliteRoleRepository::usuario_tiene_permiso` (siempre `false`), esto
    // fallaba con `PermissionDenied` — `es_privilegiado` nunca daba `true`.
    let sub = servicio
        .crear(user_id, Uuid::now_v7(), b"sub-cifrada", b"nonce", Some(raiz.id))
        .await
        .expect("anidar una carpeta debe funcionar para el único usuario local");

    let arbol = servicio.listar_arbol(user_id).await.unwrap();
    assert_eq!(arbol.len(), 2);
    let nodo_sub = arbol.iter().find(|n| n.folder_id == sub.id).expect("la subcarpeta debe estar en el árbol");
    assert_eq!(nodo_sub.parent_folder_id, Some(raiz.id));
    assert_eq!(nodo_sub.name_ciphertext, b"sub-cifrada");
}

#[tokio::test]
async fn excede_la_profundidad_maxima_de_carpetas() {
    let pool = pool_de_prueba().await;
    let repos = ReposDeCarpetas::nuevos(&pool);
    let servicio = repos.servicio();
    let user_id = Uuid::now_v7();

    let nivel1 = servicio.crear(user_id, Uuid::now_v7(), b"n1", b"n", None).await.unwrap();
    let nivel2 = servicio.crear(user_id, Uuid::now_v7(), b"n2", b"n", Some(nivel1.id)).await.unwrap();
    let nivel3 = servicio.crear(user_id, Uuid::now_v7(), b"n3", b"n", Some(nivel2.id)).await.unwrap();

    let resultado = servicio.crear(user_id, Uuid::now_v7(), b"n4", b"n", Some(nivel3.id)).await;
    assert!(matches!(resultado, Err(DomainError::ValidacionInvalida(_))), "un 4to nivel debe rechazarse (máximo 3)");
}

#[tokio::test]
async fn mover_una_carpeta_detecta_ciclos() {
    let pool = pool_de_prueba().await;
    let repos = ReposDeCarpetas::nuevos(&pool);
    let servicio = repos.servicio();
    let user_id = Uuid::now_v7();

    let raiz = servicio.crear(user_id, Uuid::now_v7(), b"raiz", b"n", None).await.unwrap();
    let sub = servicio.crear(user_id, Uuid::now_v7(), b"sub", b"n", Some(raiz.id)).await.unwrap();

    // Mover `raiz` dentro de su propia descendiente (`sub`) crearía un ciclo.
    let resultado = servicio.mover(user_id, raiz.id, Some(sub.id)).await;
    assert!(matches!(resultado, Err(DomainError::ValidacionInvalida(_))), "mover una carpeta dentro de su descendiente debe rechazarse");

    // Reposicionar a la raíz (sacarla de cualquier padre) sigue funcionando.
    servicio.mover(user_id, sub.id, None).await.expect("reposicionar a la raíz debe funcionar");
    let arbol = servicio.listar_arbol(user_id).await.unwrap();
    let nodo_sub = arbol.iter().find(|n| n.folder_id == sub.id).unwrap();
    assert_eq!(nodo_sub.parent_folder_id, None);
}

#[tokio::test]
async fn mover_un_recurso_a_una_carpeta_exige_ser_el_dueno() {
    let pool = pool_de_prueba().await;
    let repos = ReposDeCarpetas::nuevos(&pool);
    let servicio = repos.servicio();
    let recursos = SqliteResourceRepository { pool: pool.clone() };
    let items = SqliteFolderItemRepository { pool: pool.clone() };

    let dueno = Uuid::now_v7();
    let otro = Uuid::now_v7();
    let recurso =
        recursos.crear(Uuid::now_v7(), Uuid::now_v7(), b"metadata", b"nonce", dueno, None).await.expect("crear recurso de prueba");
    let carpeta = servicio.crear(dueno, Uuid::now_v7(), b"carpeta", b"n", None).await.unwrap();

    // El dueño puede posicionar su propio recurso.
    servicio.mover_recurso(dueno, recurso.id, Some(carpeta.id)).await.expect("el dueño debe poder mover su recurso");
    let posiciones = items.posiciones_de_recursos(dueno).await.unwrap();
    assert_eq!(posiciones.get(&recurso.id), Some(&carpeta.id));

    // Otro usuario (sin `created_by` sobre ese recurso) no puede.
    let resultado = servicio.mover_recurso(otro, recurso.id, Some(carpeta.id)).await;
    assert!(matches!(resultado, Err(DomainError::PermissionDenied)), "un usuario sin permiso sobre el recurso no debe poder moverlo");
}

#[tokio::test]
async fn tags_crear_aplicar_listar_y_quitar() {
    let pool = pool_de_prueba().await;
    let tags = SqliteTagRepository { pool: pool.clone() };
    let permisos = SqlitePermissionRepository { pool: pool.clone() };
    let recursos = SqliteResourceRepository { pool: pool.clone() };
    let servicio = TagService { tags: &tags, permisos: &permisos };

    let user_id = Uuid::now_v7();
    let recurso = recursos.crear(Uuid::now_v7(), Uuid::now_v7(), b"m", b"n", user_id, None).await.unwrap();

    let tag = servicio.crear(user_id, true, Uuid::now_v7(), "trabajo", false).await.unwrap();
    assert_eq!(tag.name, "trabajo");
    assert!(!tag.is_shared);

    servicio.aplicar(user_id, recurso.id, tag.id).await.expect("aplicar el propio tag al propio recurso debe funcionar");

    let disponibles = servicio.listar_disponibles(user_id).await.unwrap();
    assert_eq!(disponibles.len(), 1);

    let con_tag = servicio.recursos_por_tag(user_id, tag.id).await.unwrap();
    assert_eq!(con_tag, vec![recurso.id]);

    servicio.quitar(user_id, recurso.id, tag.id).await.unwrap();
    assert!(servicio.recursos_por_tag(user_id, tag.id).await.unwrap().is_empty());
}

#[tokio::test]
async fn un_tag_personal_ajeno_no_se_puede_aplicar() {
    let pool = pool_de_prueba().await;
    let tags = SqliteTagRepository { pool: pool.clone() };
    let permisos = SqlitePermissionRepository { pool: pool.clone() };
    let recursos = SqliteResourceRepository { pool: pool.clone() };
    let servicio = TagService { tags: &tags, permisos: &permisos };

    let dueno_tag = Uuid::now_v7();
    let otro = Uuid::now_v7();
    let tag = servicio.crear(dueno_tag, true, Uuid::now_v7(), "personal-de-dueno_tag", false).await.unwrap();
    let recurso_de_otro = recursos.crear(Uuid::now_v7(), Uuid::now_v7(), b"m", b"n", otro, None).await.unwrap();

    let resultado = servicio.aplicar(otro, recurso_de_otro.id, tag.id).await;
    assert!(matches!(resultado, Err(DomainError::PermissionDenied)), "un tag personal ajeno no debe poder aplicarse");
}
