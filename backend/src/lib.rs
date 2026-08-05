// Autor: Athan Espinoza

pub mod admin;
pub mod audit;
pub mod auth;
pub mod b64;
pub mod config;
pub mod devices;
pub mod error;
pub mod eventos;
pub mod folders;
pub mod groups;
pub mod metadata;
pub mod mfa;
pub mod notificaciones;
pub mod observabilidad;
pub mod passkeys;
pub mod rate_limit;
pub mod resources;
pub mod state;
pub mod tags;

use std::time::Duration;

use axum::routing::{get, post, put};
use axum::Router;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::GovernorLayer;
use tower_http::trace::TraceLayer;
use tracing::field::Empty;

use state::AppState;

/// Carga la identidad Ed25519 propia del servidor (`GET /auth/server-key`) —
/// se genera una sola vez, en el primer arranque. No es un secreto
/// zero-knowledge del usuario, es la identidad del propio servidor.
pub async fn cargar_o_generar_server_key(pool: &sqlx::PgPool) -> anyhow::Result<[u8; 32]> {
    if let Some(fila) = sqlx::query!("select public_key_ed25519 from server_keys where id = 1")
        .fetch_optional(pool)
        .await?
    {
        return Ok(fila.public_key_ed25519.try_into().expect("32 bytes"));
    }

    let par = ellkan_crypto::claves::KeypairFirma::generar();
    let publica = par.verificadora().to_bytes();
    let privada = par.firmante().to_bytes();

    sqlx::query!(
        "insert into server_keys (id, public_key_ed25519, private_key_ed25519) values (1, $1, $2)
         on conflict (id) do nothing",
        &publica[..],
        &privada[..],
    )
    .execute(pool)
    .await?;

    Ok(publica)
}

/// Chequeo real contra Postgres, no un 200 fijo: si la DB no responde, el
/// operador tiene que verlo acá.
async fn healthz(
    axum::extract::State(state): axum::extract::State<AppState>,
) -> Result<&'static str, axum::http::StatusCode> {
    sqlx::query("select 1")
        .execute(&state.pool)
        .await
        .map(|_| "ok")
        .map_err(|_| axum::http::StatusCode::SERVICE_UNAVAILABLE)
}

/// Conecta, corre migraciones y arma el `AppState` — usado por el binario y
/// por los tests de integración (misma inicialización, sin duplicar lógica).
pub async fn construir_estado(
    database_url: &str,
    secrets_key: ellkan_crypto::secretos::ClaveSecreta32,
) -> anyhow::Result<AppState> {
    let pool = sqlx::PgPool::connect(database_url).await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    let server_public_key = cargar_o_generar_server_key(&pool).await?;
    Ok(AppState::nuevo(pool, server_public_key, secrets_key))
}

/// Arma el router completo — separado de `main()` para que los tests de
/// integración puedan levantar el mismo árbol de rutas sin duplicar nada.
pub fn construir_router(estado: AppState) -> Router {
    let governor_conf = GovernorConfigBuilder::default()
        .per_second(2)
        .burst_size(20)
        .finish()
        .expect("configuración de rate limiting válida");

    let limiter = governor_conf.limiter().clone();
    tokio::spawn(async move {
        let mut intervalo = tokio::time::interval(Duration::from_secs(60));
        loop {
            intervalo.tick().await;
            limiter.retain_recent();
        }
    });

    // Consumidor de domain events (F-02: dispositivo no reconocido -> cola de
    // email) + poller de envío (stub en Fase 0, ver notificaciones.rs).
    notificaciones::spawn_consumidor_de_eventos(&estado.eventos, estado.emails.clone());
    notificaciones::spawn_poller_de_envio(estado.emails.clone(), Duration::from_secs(5));

    // F-33: consumidor de `MetadataKeyRotationStarted` + reconciliación de
    // una rotación que ya estuviera en curso si el proceso se reinició.
    metadata::rotacion::spawn_consumidor(&estado.eventos, estado.claves_metadata.clone());
    tokio::spawn(metadata::rotacion::reconciliar_al_arrancar(estado.claves_metadata.clone()));

    // F-13: consumidor de `DomainEvent::Auditoria` — persiste cada entrada
    // de forma asíncrona, nunca dentro de la transacción de la acción que
    // audita (ver `audit::consumidor`).
    audit::consumidor::spawn_consumidor(&estado.eventos, estado.audit_log.clone());

    let webauthn_router = Router::new()
        .route("/register/options", post(passkeys::handlers::register_options))
        .route("/register/verify", post(passkeys::handlers::register_verify))
        .route("/login/options", post(passkeys::handlers::login_options))
        .route("/login/verify", post(passkeys::handlers::login_verify));

    let device_approval_router = Router::new()
        .route("/request", post(devices::handlers::solicitar_aprobacion))
        .route(
            "/{id}",
            get(devices::handlers::estado_aprobacion),
        )
        .route("/{id}/approve", post(devices::handlers::aprobar));

    // F-14: rate limit dedicado, keyed por sesión parcial — más estricto que
    // el general, ver `rate_limit::limitar_mfa_por_sesion`.
    let auth_mfa_router = Router::new().route("/verify", post(mfa::handlers::verify)).route_layer(
        axum::middleware::from_fn_with_state(estado.clone(), rate_limit::limitar_mfa_por_sesion),
    );

    let auth_router = Router::new()
        .route("/register", post(auth::handlers::register))
        .route("/server-key", get(auth::handlers::server_key))
        .route("/challenge", post(auth::handlers::challenge))
        .route("/verify", post(auth::handlers::verify))
        .route("/verify-device", post(auth::handlers::verify_device))
        .route("/logout", post(auth::handlers::logout))
        .nest("/webauthn", webauthn_router)
        .nest("/device-approval", device_approval_router)
        .nest("/mfa", auth_mfa_router);

    let me_devices_router = Router::new()
        .route("/", get(devices::handlers::listar_confiables))
        .route("/trust", post(devices::handlers::marcar_confiable))
        .route("/{id}", axum::routing::delete(devices::handlers::revocar))
        .route("/pending-approvals", get(devices::handlers::listar_pendientes));

    let admin_device_approval_policy_router = Router::new()
        .route("/", get(devices::handlers::politica).put(devices::handlers::actualizar_politica));

    let me_mfa_totp_router = Router::new()
        .route("/setup", post(mfa::handlers::setup_totp))
        .route("/confirm", post(mfa::handlers::confirm_totp));

    let admin_mfa_policy_router = Router::new()
        .route("/", get(mfa::handlers::politica).put(mfa::handlers::actualizar_politica));

    let resources_router = Router::new()
        .route("/", get(resources::handlers::listar).post(resources::handlers::crear))
        .route("/{id}", get(resources::handlers::obtener))
        .route("/{id}/secret", get(resources::handlers::obtener_secreto))
        .route("/{id}/share", post(resources::handlers::compartir))
        .route(
            "/{id}/tags/{tag_id}",
            post(tags::handlers::aplicar).delete(tags::handlers::quitar),
        )
        .route("/{id}/rekey-metadata", post(resources::handlers::rekey_metadata))
        .route("/{id}/totp", get(resources::handlers::totp))
        .route_layer(axum::middleware::from_fn_with_state(
            estado.clone(),
            rate_limit::limitar_por_usuario,
        ));

    let tags_router =
        Router::new().route("/", get(tags::handlers::listar).post(tags::handlers::crear));

    let groups_router = Router::new()
        .route("/", get(groups::handlers::listar).post(groups::handlers::crear))
        .route("/{id}", get(groups::handlers::obtener).delete(groups::handlers::eliminar))
        .route("/{id}/subgroups", get(groups::handlers::subgrupos))
        .route("/{id}/move", put(groups::handlers::mover))
        .route(
            "/{id}/members/{user_id}",
            post(groups::handlers::agregar_miembro)
                .delete(groups::handlers::quitar_miembro)
                .put(groups::handlers::set_manager),
        );

    let metadata_keys_router = Router::new().route("/", get(metadata::handlers::listar));
    let admin_metadata_keys_router = Router::new()
        .route("/", post(metadata::handlers::crear))
        .route("/rotate", post(metadata::handlers::rotar))
        .route("/rotation-status", get(metadata::handlers::rotation_status));

    let admin_roles_router = Router::new()
        .route("/", get(admin::handlers::listar).post(admin::handlers::crear))
        .route("/{id}", put(admin::handlers::actualizar_permisos));

    let admin_audit_log_router = Router::new()
        .route("/", get(audit::handlers::listar))
        .route("/export", get(audit::handlers::exportar));

    let folders_router = Router::new()
        .route("/", get(folders::handlers::listar).post(folders::handlers::crear))
        .route("/{id}/move", put(folders::handlers::mover));

    Router::new()
        .route("/healthz", get(healthz))
        .route("/users/{email}/public-key", get(auth::handlers::public_key))
        .nest("/auth", auth_router)
        .nest("/resources", resources_router)
        .nest("/admin/roles", admin_roles_router)
        .nest("/admin/audit-log", admin_audit_log_router)
        .nest("/folders", folders_router)
        .nest("/tags", tags_router)
        .nest("/metadata-keys", metadata_keys_router)
        .nest("/admin/metadata-keys", admin_metadata_keys_router)
        .nest("/groups", groups_router)
        .nest("/me/devices", me_devices_router)
        .nest("/me/mfa/totp", me_mfa_totp_router)
        .nest("/admin/device-approval-policy", admin_device_approval_policy_router)
        .nest("/admin/mfa-policy", admin_mfa_policy_router)
        .layer(GovernorLayer::new(governor_conf))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|req: &axum::http::Request<_>| {
                    // Sólo método + ruta (sin query string) — nunca headers ni
                    // body. `actor_id` se completa después, si la ruta exige
                    // sesión, en `AuthenticatedUser::from_request_parts`.
                    tracing::info_span!(
                        "http_request",
                        method = %req.method(),
                        path = %req.uri().path(),
                        status = Empty,
                        actor_id = Empty,
                    )
                })
                .on_response(
                    |res: &axum::http::Response<_>, latencia: std::time::Duration, span: &tracing::Span| {
                        span.record("status", res.status().as_u16());
                        tracing::debug!(latencia_ms = latencia.as_millis(), "solicitud procesada");
                    },
                ),
        )
        .with_state(estado)
}
