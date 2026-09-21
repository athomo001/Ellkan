// Autor: Athan Espinoza

//! Sincronización con concurrencia real (fase 3.2 del plan de escritorio).
//!
//! El motor de sync (`frontend/src/lib/sync/motor.ts`) empuja cambios locales
//! con `PUT /resources/{id}` + `If-Match` (`updated_at`), y todo su manejo de
//! conflictos se apoya en que ese chequeo sea ATÓMICO: si dos clientes editan
//! el mismo recurso a la vez, uno gana y el otro recibe un conflicto — nunca
//! un "gana el último" silencioso que pise el cambio del otro. Acá se prueba
//! esa garantía con escrituras que compiten de verdad (dos tareas a la vez),
//! y que la bóveda local sigue funcionando sin ningún servidor.
//!
//! Sólo compila/corre con `--features desktop`.
#![cfg(feature = "desktop")]

use ellkan_backend::desktop::repositories::admin::SqliteRoleRepository;
use ellkan_backend::desktop::repositories::folders::SqliteFolderItemRepository;
use ellkan_backend::desktop::repositories::groups::SqliteGroupMemberRepository;
use ellkan_backend::desktop::repositories::resources::{
    SqlitePermissionRepository, SqliteResourceRepository, SqliteResourceTypeRepository, SqliteSecretEnvelopeRepository,
};
use ellkan_backend::desktop::{cargar_config, guardar_config, ConfigSyncRemoto};
use ellkan_backend::error::DomainError;
use ellkan_backend::eventos;
use ellkan_backend::resources::models::EnvelopeInput;
use ellkan_backend::resources::repository::ResourceRepository;
use ellkan_backend::resources::service::ResourceService;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;
use uuid::Uuid;

async fn pool_de_prueba() -> SqlitePool {
    let pool = SqlitePoolOptions::new().max_connections(8).connect("sqlite::memory:").await.expect("conectar sqlite en memoria");
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

fn envelope(user_id: Uuid, marca: &str) -> EnvelopeInput {
    EnvelopeInput {
        user_id,
        sealed_dek: format!("dek-{marca}").into_bytes(),
        secret_ciphertext: format!("secreto-{marca}").into_bytes(),
        secret_nonce: format!("nonce-{marca}").into_bytes(),
    }
}

/// Una edición desde "otro cliente": arma sus propios repos (mismo pool) y
/// guarda partiendo de `base`. Corre en su propia tarea para competir de verdad.
fn editar_como_cliente(pool: SqlitePool, recurso_id: Uuid, user_id: Uuid, base: time::OffsetDateTime, marca: String) -> tokio::task::JoinHandle<Result<String, DomainError>> {
    tokio::spawn(async move {
        let repos = Repos::nuevos(&pool);
        repos
            .servicio()
            .editar(recurso_id, user_id, base, marca.as_bytes(), b"nonce", vec![envelope(user_id, &marca)])
            .await
            .map(|_| marca)
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dos_ediciones_a_la_vez_del_mismo_recurso_gana_una_y_la_otra_recibe_conflicto() {
    let pool = pool_de_prueba().await;
    let repos = Repos::nuevos(&pool);
    let user_id = Uuid::now_v7();

    // Varias vueltas: una carrera sólo sale mal a veces, una sola no alcanza.
    for vuelta in 0..25 {
        let recurso = repos.recursos.crear(Uuid::now_v7(), Uuid::now_v7(), b"metadata-base", b"nonce-base", user_id, None).await.unwrap();
        let base = recurso.updated_at;

        // Dos "clientes" que partieron de la MISMA versión y guardan a la vez.
        let a = editar_como_cliente(pool.clone(), recurso.id, user_id, base, "A".to_string());
        let b = editar_como_cliente(pool.clone(), recurso.id, user_id, base, "B".to_string());
        let (resultado_a, resultado_b) = (a.await.unwrap(), b.await.unwrap());

        let ganadores = [&resultado_a, &resultado_b].iter().filter(|r| r.is_ok()).count();
        let conflictos = [&resultado_a, &resultado_b].iter().filter(|r| matches!(r, Err(DomainError::Conflict))).count();
        assert_eq!(ganadores, 1, "vuelta {vuelta}: exactamente una edición debe ganar");
        assert_eq!(conflictos, 1, "vuelta {vuelta}: la otra debe recibir conflicto, no pisar en silencio");

        // Lo que quedó guardado es EXACTAMENTE lo del ganador (nada mezclado, nada perdido).
        let quedo = repos.recursos.buscar(recurso.id).await.unwrap().expect("el recurso sigue existiendo");
        let esperado: &[u8] = if resultado_a.is_ok() { b"A" } else { b"B" };
        assert_eq!(quedo.metadata_ciphertext, esperado, "vuelta {vuelta}");
        assert!(quedo.updated_at > base, "vuelta {vuelta}: la versión avanzó");
    }
}

#[tokio::test]
async fn el_cliente_que_perdio_la_carrera_reintenta_con_la_version_nueva_y_no_pierde_su_cambio() {
    // Es lo que hace el motor de sync: empujar, recibir conflicto, traer lo
    // nuevo (`GET /sync`) y volver a aplicar sobre esa versión.
    let pool = pool_de_prueba().await;
    let repos = Repos::nuevos(&pool);
    let servicio = repos.servicio();
    let user_id = Uuid::now_v7();

    let recurso = repos.recursos.crear(Uuid::now_v7(), Uuid::now_v7(), b"v0", b"n0", user_id, None).await.unwrap();
    let base = recurso.updated_at;

    // El cliente A guarda primero.
    let de_a = servicio.editar(recurso.id, user_id, base, b"v1-de-A", b"n1", vec![envelope(user_id, "A")]).await.expect("A guarda");

    // El cliente B, que partió de `base`, choca.
    let choque = servicio.editar(recurso.id, user_id, base, b"v1-de-B", b"n1", vec![envelope(user_id, "B")]).await;
    assert!(matches!(choque, Err(DomainError::Conflict)));

    // B trae la versión actual (la de A) y reintenta sobre ella.
    let actual = repos.recursos.buscar(recurso.id).await.unwrap().unwrap();
    assert_eq!(actual.metadata_ciphertext, b"v1-de-A", "B ve lo que guardó A");
    let de_b = servicio
        .editar(recurso.id, user_id, actual.updated_at, b"v2-de-B", b"n2", vec![envelope(user_id, "B")])
        .await
        .expect("B reintenta sobre la versión nueva");

    assert!(de_b.updated_at > de_a.updated_at);
    let final_ = repos.recursos.buscar(recurso.id).await.unwrap().unwrap();
    assert_eq!(final_.metadata_ciphertext, b"v2-de-B", "el cambio de B llegó, encima del de A");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn muchos_clientes_a_la_vez_nunca_pierden_un_cambio_en_silencio() {
    // 6 clientes editan el mismo recurso a la vez, cada uno partiendo de la
    // versión que vio al principio: sólo uno puede ganar; el resto tiene que
    // enterarse (conflicto), no creer que guardó.
    let pool = pool_de_prueba().await;
    let repos = Repos::nuevos(&pool);
    let user_id = Uuid::now_v7();
    let recurso = repos.recursos.crear(Uuid::now_v7(), Uuid::now_v7(), b"base", b"n", user_id, None).await.unwrap();

    let tareas: Vec<_> = (0..6).map(|i| editar_como_cliente(pool.clone(), recurso.id, user_id, recurso.updated_at, format!("cliente-{i}"))).collect();
    let mut resultados = Vec::new();
    for t in tareas {
        resultados.push(t.await.unwrap());
    }

    let ganadores: Vec<&String> = resultados.iter().filter_map(|r| r.as_ref().ok()).collect();
    assert_eq!(ganadores.len(), 1, "sólo uno pudo guardar: {resultados:?}");
    assert_eq!(resultados.iter().filter(|r| matches!(r, Err(DomainError::Conflict))).count(), 5);
    let quedo = repos.recursos.buscar(recurso.id).await.unwrap().unwrap();
    assert_eq!(quedo.metadata_ciphertext, ganadores[0].as_bytes());
}

#[tokio::test]
async fn desvincular_el_servidor_deja_la_boveda_funcionando_en_local() {
    let pool = pool_de_prueba().await;
    let repos = Repos::nuevos(&pool);
    let servicio = repos.servicio();
    let user_id = Uuid::now_v7();
    let datadir = std::env::temp_dir().join(format!("ellkan_test_desvincular_{}", Uuid::now_v7()));
    std::fs::create_dir_all(&datadir).unwrap();

    // Conectada: hay una configuración de servidor remoto guardada.
    let mut config = cargar_config(&datadir).unwrap();
    config.sync_remoto = ConfigSyncRemoto {
        server_url: Some("https://ellkan.ejemplo.test".into()),
        sync_token: Some("token".into()),
        last_sync_at: Some("2026-09-20T12:00:00Z".into()),
    };
    guardar_config(&datadir, &config).unwrap();
    let recurso = repos.recursos.crear(Uuid::now_v7(), Uuid::now_v7(), b"antes", b"n", user_id, None).await.unwrap();

    // Desvincular: se olvida el servidor (lo mismo que hace la app).
    let mut config = cargar_config(&datadir).unwrap();
    config.sync_remoto = ConfigSyncRemoto::default();
    guardar_config(&datadir, &config).unwrap();
    assert!(cargar_config(&datadir).unwrap().sync_remoto.server_url.is_none());

    // La bóveda sigue entera y se puede seguir usando, sin ningún servidor.
    let visibles = servicio.listar_visibles(user_id).await.unwrap();
    assert_eq!(visibles.len(), 1, "el recurso creado estando conectada sigue ahí");
    let editado = servicio.editar(recurso.id, user_id, recurso.updated_at, b"despues", b"n2", vec![envelope(user_id, "local")]).await;
    assert!(editado.is_ok(), "se puede editar sin servidor");
    let nuevo = repos.recursos.crear(Uuid::now_v7(), Uuid::now_v7(), b"nuevo", b"n", user_id, None).await;
    assert!(nuevo.is_ok(), "y crear recursos nuevos");
    assert_eq!(servicio.listar_visibles(user_id).await.unwrap().len(), 2);
}
