// Autor: Athan Espinoza

pub mod account_recovery;
pub mod admin;
pub mod audit;
pub mod auth;
pub mod b64;
pub mod config;
pub mod devices;
pub mod directory_sync;
pub mod emergency_access;
pub mod error;
pub mod eventos;
pub mod export;
pub mod external_shares;
pub mod folders;
pub mod groups;
pub mod me;
pub mod metadata;
pub mod mfa;
pub mod notificaciones;
pub mod observabilidad;
pub mod passkeys;
pub mod password_policy;
pub mod rate_limit;
pub mod reports;
pub mod resources;
pub mod retention;
pub mod scim;
pub mod smtp_config;
pub mod sso;
pub mod state;
pub mod tags;
pub mod users_admin;

use std::time::Duration;

use axum::http::{HeaderName, HeaderValue};
use axum::routing::{delete, get, post, put};
use axum::Router;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::GovernorLayer;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;
use tracing::field::Empty;

use state::AppState;

/// F-30/`04-seguridad-y-amenazas.md` §4: CSP estricta porque todo el modelo
/// zero-knowledge depende de que el JS/WASM servido sea exactamente el
/// correcto — si el bundle se altera (build/CDN comprometido), el atacante
/// controla el código que descifra sin romper ningún cifrado. `'wasm-unsafe-eval'`
/// es la directiva específica de CSP nivel 3 que exige WASM, no
/// `unsafe-eval` genérico. `style-src` deliberadamente sin restringir (no
/// pedido por la spec).
///
/// **`script-src` NO va acá** — corrección real, no la nota original de este
/// comentario (que asumía "Svelte no inyecta `<script>` inline" sin haberlo
/// probado nunca contra un navegador real): SvelteKit sí inyecta un
/// `<script>` inline chico en `index.html` (el bootstrap que hace
/// `Promise.all([import(...)])` para arrancar la app) — sin `unsafe-inline`,
/// ese script necesita su hash SHA-256 exacto en `script-src`, y ese hash
/// cambia en cada build (los nombres de archivo hasheados cambian). Un
/// header estático con un hash fijo se habría roto en el próximo build. La
/// solución real: `frontend/vite.config.ts` (`csp: { mode: 'hash' }`) hace
/// que SvelteKit calcule el hash correcto en cada build y lo inyecte solo
/// en un `<meta http-equiv="Content-Security-Policy">` — `script-src` queda
/// gobernado por ese `<meta>`, nunca por este header. El resto de las
/// directivas sí puede (y debe) seguir acá: `frame-ancestors` en particular
/// **tiene que** ser un header, un `<meta>` lo ignora por especificación.
const CSP: &str = "object-src 'none'; frame-ancestors 'none'; base-uri 'self'";

fn header_estatico(nombre: &'static str, valor: &'static str) -> SetResponseHeaderLayer<HeaderValue> {
    SetResponseHeaderLayer::overriding(HeaderName::from_static(nombre), HeaderValue::from_static(valor))
}

/// PBL-08-005 (`04-seguridad-y-amenazas.md` línea 125): CSP sola no alcanza,
/// un set de headers. Aplicado globalmente (incluida la API JSON) — inerte
/// ahí, pero evita duplicar la capa entre rutas de API y estáticas.
fn capa_headers_seguridad(router: Router) -> Router {
    router
        .layer(header_estatico("content-security-policy", CSP))
        .layer(header_estatico("x-content-type-options", "nosniff"))
        .layer(header_estatico("referrer-policy", "same-origin"))
        .layer(header_estatico("cross-origin-opener-policy", "same-origin"))
        .layer(header_estatico("cross-origin-resource-policy", "same-origin"))
}

/// `ELLKAN_FRONTEND_DIST` (default `frontend/build`, relativo al `cwd` del
/// proceso) en vez de un parámetro de `construir_router` — mismo criterio
/// que `ELLKAN_RP_ID`/`ELLKAN_OTEL_ENDPOINT` (`state.rs`/`main.rs`): evita
/// romper la firma que ya usan ~20 archivos de test.
fn dist_frontend() -> String {
    std::env::var("ELLKAN_FRONTEND_DIST").unwrap_or_else(|_| "frontend/build".to_string())
}

/// Sirve el build estático de `frontend/` (adapter-static + fallback SPA,
/// `vite.config.ts`) con `index.html` como fallback de cualquier ruta que
/// no matchee un archivo real — el routing en tres capas (07-frontend-web.md
/// §3) se resuelve client-side contra la sesión, no server-side por ruta.
///
/// **No usa `ServeDir::not_found_service`**: esa API sirve el contenido de
/// respaldo pero fuerza el status a `404` (es, literalmente, para páginas
/// de error) — un `/vault` pedido de entrada (F5, o un link directo) volvería
/// 404 aunque el body traiga el shell de la SPA. Acá se maneja a mano para
/// devolver `200`: primero `ServeDir` intenta un archivo real (JS/CSS/wasm,
/// `sí` deben 404 si faltan), y sólo si no matchea nada se sirve
/// `index.html` reescribiendo el status a `200`. Si el directorio no existe
/// (dev sin build, o los tests de integración) cae al mismo 404 — no falla
/// el arranque; en desarrollo el frontend se sirve aparte vía `pnpm dev`.
async fn fallback_frontend(req: axum::extract::Request) -> axum::response::Response {
    use axum::response::IntoResponse;
    use tower::ServiceExt;

    let dist = dist_frontend();

    let respuesta_archivo = ServeDir::new(&dist).oneshot(req).await.into_response();
    if respuesta_archivo.status() != axum::http::StatusCode::NOT_FOUND {
        return respuesta_archivo;
    }

    let req_index = axum::http::Request::builder()
        .uri("/index.html")
        .body(axum::body::Body::empty())
        .expect("request de index.html válido");

    match ServeFile::new(format!("{dist}/index.html")).oneshot(req_index).await {
        Ok(mut respuesta) => {
            *respuesta.status_mut() = axum::http::StatusCode::OK;
            respuesta.into_response()
        }
        Err(_) => axum::http::StatusCode::NOT_FOUND.into_response(),
    }
}

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
/// `ldap3` (F-19) elige explícitamente el provider `ring` de `rustls`;
/// `lettre`/`reqwest`/`hyper-rustls` traen `aws-lc-rs` por default — sin
/// instalar uno de los dos como provider de proceso antes de que cualquiera
/// lo necesite, `rustls` no puede elegir solo y entra en pánico en runtime.
/// `Once` porque en tests varios `#[tokio::test]` corren en el mismo
/// proceso y `install_default` sólo puede llamarse una vez.
fn instalar_crypto_provider_tls() {
    static UNA_VEZ: std::sync::Once = std::sync::Once::new();
    UNA_VEZ.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

pub async fn construir_estado(
    database_url: &str,
    secrets_key: ellkan_crypto::secretos::ClaveSecreta32,
) -> anyhow::Result<AppState> {
    instalar_crypto_provider_tls();
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
    // email) + poller de envío — manda SMTP real si `smtp_config` (Parte A,
    // editable desde el admin) está configurada, si no mantiene el stub
    // (ver notificaciones.rs). A diferencia de la versión anterior por
    // variable de entorno, la config se relee de la base en cada tick, así
    // que un cambio del admin aplica sin reiniciar el proceso.
    notificaciones::spawn_consumidor_de_eventos(&estado.eventos, estado.emails.clone());
    notificaciones::spawn_poller_de_envio(
        estado.emails.clone(),
        estado.smtp_config.clone(),
        estado.secrets_key.clone(),
        Duration::from_secs(5),
    );

    // F-33: consumidor de `MetadataKeyRotationStarted` + reconciliación de
    // una rotación que ya estuviera en curso si el proceso se reinició.
    metadata::rotacion::spawn_consumidor(&estado.eventos, estado.claves_metadata.clone());
    tokio::spawn(metadata::rotacion::reconciliar_al_arrancar(estado.claves_metadata.clone()));

    // F-13: consumidor de `DomainEvent::Auditoria` — persiste cada entrada
    // de forma asíncrona, nunca dentro de la transacción de la acción que
    // audita (ver `audit::consumidor`).
    audit::consumidor::spawn_consumidor(&estado.eventos, estado.audit_log.clone());

    // F-40: purga física de lo soft-deleted vencido — diaria, idempotente,
    // sin cursor propio (cada corrida sólo actúa sobre lo que siga vencido).
    retention::job::spawn(
        &estado.eventos,
        estado.retention_policy.clone(),
        estado.purge.clone(),
        Duration::from_secs(86_400),
    );

    // F-36: resuelve `granted_by_timeout` cuando una solicitud de emergency
    // access vence sin respuesta del titular — horaria, para no dejar a un
    // contacto esperando más de una hora de más sobre `wait_time_days`.
    emergency_access::job::spawn(
        &estado.eventos,
        estado.emergency_access.clone(),
        estado.emergency_access_requests.clone(),
        Duration::from_secs(3_600),
    );

    // F-26: quema (borra ciphertext) de external shares vencidos que nadie
    // llegó a abrir nunca — intervalo corto, ver comentario en
    // `external_shares::job`.
    external_shares::job::spawn(&estado.eventos, estado.external_shares.clone(), Duration::from_secs(300));

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

    let sso_router = Router::new()
        .route("/{provider}/redirect", get(sso::handlers::redirect))
        .route("/{provider}/callback", get(sso::handlers::callback));

    let auth_router = Router::new()
        .route("/register", post(auth::handlers::register))
        .route("/server-key", get(auth::handlers::server_key))
        .route("/challenge", post(auth::handlers::challenge))
        .route("/key-material", post(auth::handlers::key_material))
        .route("/verify", post(auth::handlers::verify))
        .route("/verify-device", post(auth::handlers::verify_device))
        .route("/logout", post(auth::handlers::logout))
        .nest("/webauthn", webauthn_router)
        .nest("/device-approval", device_approval_router)
        .nest("/mfa", auth_mfa_router)
        .nest("/sso", sso_router);

    let me_devices_router = Router::new()
        .route("/", get(devices::handlers::listar_confiables))
        .route("/trust", post(devices::handlers::marcar_confiable))
        .route("/{id}", axum::routing::delete(devices::handlers::revocar))
        .route("/pending-approvals", get(devices::handlers::listar_pendientes));

    // F-03 (PRF): listar/revocar passkeys propias — a diferencia de
    // `/auth/webauthn/*` (sin sesión, ceremonia de alta/login), esto exige
    // sesión activa, mismo criterio que `/me/devices`.
    let me_passkeys_router = Router::new()
        .route("/", get(passkeys::handlers::listar))
        .route("/{id}", axum::routing::delete(passkeys::handlers::revocar));

    let admin_device_approval_policy_router = Router::new()
        .route("/", get(devices::handlers::politica).put(devices::handlers::actualizar_politica));

    let me_preferences_router =
        Router::new().route("/", get(me::handlers::obtener).put(me::handlers::actualizar));

    let me_mfa_totp_router = Router::new()
        .route("/setup", post(mfa::handlers::setup_totp))
        .route("/confirm", post(mfa::handlers::confirm_totp));

    let admin_mfa_policy_router = Router::new()
        .route("/", get(mfa::handlers::politica).put(mfa::handlers::actualizar_politica));

    let admin_smtp_config_router = Router::new()
        .route("/", get(smtp_config::handlers::obtener).put(smtp_config::handlers::actualizar));

    let resources_router = Router::new()
        .route("/", get(resources::handlers::listar).post(resources::handlers::crear))
        .route(
            "/{id}",
            get(resources::handlers::obtener).put(resources::handlers::actualizar),
        )
        .route("/{id}/recipients", get(resources::handlers::recipients))
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
        .route("/{id}/resources", get(groups::handlers::recursos_compartidos))
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

    let admin_password_policy_router = Router::new()
        .route("/", get(password_policy::handlers::politica).put(password_policy::handlers::actualizar_politica));

    let admin_retention_policy_router = Router::new()
        .route("/", get(retention::handlers::politica).put(retention::handlers::actualizar_politica));

    let admin_account_recovery_policy_router = Router::new().route(
        "/",
        get(account_recovery::handlers::politica).put(account_recovery::handlers::actualizar_politica),
    );

    let account_recovery_router = Router::new()
        .route("/org-public-key", get(account_recovery::handlers::org_public_key))
        .route("/enroll", post(account_recovery::handlers::enrolar))
        .route("/requests", post(account_recovery::handlers::crear_solicitud))
        .route("/requests/{id}", get(account_recovery::handlers::estado_solicitud))
        .route("/requests/{id}/complete", post(account_recovery::handlers::completar));

    let admin_account_recovery_requests_router = Router::new()
        .route("/{id}/approve", post(account_recovery::handlers::aprobar));

    let me_emergency_access_router = Router::new()
        .route("/", get(emergency_access::handlers::listar).post(emergency_access::handlers::designar))
        .route("/{id}", delete(emergency_access::handlers::revocar))
        .route("/{id}/accept", post(emergency_access::handlers::aceptar))
        .route("/{id}/request", post(emergency_access::handlers::solicitar))
        .route("/{id}/approve", post(emergency_access::handlers::aprobar))
        .route("/{id}/reject", post(emergency_access::handlers::rechazar));

    let admin_emergency_access_policy_router = Router::new().route(
        "/",
        get(emergency_access::handlers::politica).put(emergency_access::handlers::actualizar_politica),
    );

    let admin_sso_config_router =
        Router::new().route("/", get(sso::handlers::config).put(sso::handlers::actualizar_config));

    let admin_scim_tokens_router = Router::new().route("/", post(scim::handlers::crear_token));

    let scim_users_router = Router::new()
        .route("/", get(scim::handlers::listar_usuarios).post(scim::handlers::crear_usuario))
        .route(
            "/{id}",
            get(scim::handlers::obtener_usuario).patch(scim::handlers::patch_usuario),
        );

    let admin_directory_sync_router = Router::new()
        .route(
            "/config",
            get(directory_sync::handlers::config).put(directory_sync::handlers::actualizar_config),
        )
        .route("/dry-run", post(directory_sync::handlers::dry_run))
        .route("/apply", post(directory_sync::handlers::aplicar));

    let export_policy_router = Router::new().route("/", get(export::handlers::politica));
    let admin_export_policy_router = Router::new()
        .route("/", get(export::handlers::politica_admin).put(export::handlers::actualizar_politica));
    let export_events_router = Router::new().route("/", post(export::handlers::reportar_evento));
    let admin_users_export_router = Router::new().route("/", get(export::handlers::exportar_usuarios));
    let admin_groups_export_router = Router::new().route("/", get(export::handlers::exportar_grupos));
    let admin_reports_router = Router::new().route("/{reportId}", get(reports::handlers::obtener));

    let admin_external_share_policy_router = Router::new().route(
        "/",
        get(external_shares::handlers::politica).put(external_shares::handlers::actualizar_politica),
    );

    // F-26: `GET /{id}` es el único endpoint sin sesión de toda la API —
    // necesita su propio rate limit por IP, más estricto que el general
    // (`GovernorLayer` de más abajo, 2/s burst 20), porque el id de alta
    // entropía es la única barrera contra enumeración (04-seguridad-y-amenazas.md
    // §3bis). `POST`/`DELETE` sí requieren sesión, así que van con el
    // limitador por usuario general en vez de éste.
    let external_share_governor_conf = GovernorConfigBuilder::default()
        .per_second(1)
        .burst_size(5)
        .finish()
        .expect("configuración de rate limiting de external-shares válida");
    let external_share_limiter = external_share_governor_conf.limiter().clone();
    tokio::spawn(async move {
        let mut intervalo = tokio::time::interval(Duration::from_secs(60));
        loop {
            intervalo.tick().await;
            external_share_limiter.retain_recent();
        }
    });

    let external_shares_router = Router::new()
        .route("/", post(external_shares::handlers::crear))
        .route("/{id}", delete(external_shares::handlers::revocar))
        .route_layer(axum::middleware::from_fn_with_state(estado.clone(), rate_limit::limitar_por_usuario))
        .merge(
            Router::new()
                .route("/{id}", get(external_shares::handlers::obtener))
                .layer(GovernorLayer::new(external_share_governor_conf)),
        );

    let admin_users_router = Router::new()
        .route("/", get(users_admin::handlers::listar))
        .route(
            "/{id}",
            get(users_admin::handlers::obtener).put(users_admin::handlers::actualizar_activo),
        )
        .route("/{id}/purge/dry-run", get(users_admin::handlers::purge_dry_run))
        .route("/{id}/purge", post(users_admin::handlers::purgar));

    let router = Router::new()
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
        .nest("/me/preferences", me_preferences_router)
        .nest("/me/devices", me_devices_router)
        .nest("/me/passkeys", me_passkeys_router)
        .nest("/me/mfa/totp", me_mfa_totp_router)
        .nest("/admin/device-approval-policy", admin_device_approval_policy_router)
        .nest("/admin/mfa-policy", admin_mfa_policy_router)
        .nest("/admin/smtp-config", admin_smtp_config_router)
        .nest("/admin/password-policy", admin_password_policy_router)
        .nest("/admin/data-retention-policy", admin_retention_policy_router)
        .nest("/admin/account-recovery-policy", admin_account_recovery_policy_router)
        .nest("/account-recovery", account_recovery_router)
        .nest("/admin/account-recovery/requests", admin_account_recovery_requests_router)
        .nest("/me/emergency-access", me_emergency_access_router)
        .nest("/admin/emergency-access-policy", admin_emergency_access_policy_router)
        .nest("/admin/sso-config", admin_sso_config_router)
        .nest("/admin/scim-tokens", admin_scim_tokens_router)
        .nest("/scim/v2/Users", scim_users_router)
        .nest("/admin/directory-sync", admin_directory_sync_router)
        .nest("/admin/users", admin_users_router)
        .nest("/admin/external-share-policy", admin_external_share_policy_router)
        .nest("/external-shares", external_shares_router)
        .nest("/export-policy", export_policy_router)
        .nest("/admin/export-policy", admin_export_policy_router)
        .nest("/export-events", export_events_router)
        .nest("/admin/users/export", admin_users_export_router)
        .nest("/admin/groups/export", admin_groups_export_router)
        .nest("/admin/reports", admin_reports_router)
        .fallback(fallback_frontend)
        // `route_layer` (no `layer`): a diferencia de `layer`, no envuelve al
        // `fallback` — el rate limit general es para proteger la API contra
        // abuso, no para el `ServeDir`/`ServeFile` estático (`fallback_frontend`
        // más arriba), que sirve el bundle entero (HTML, version.json, ~15+
        // chunks JS, el wasm) en paralelo por cada carga de página real. Con
        // `layer` una sola carga de página agotaba el burst (2/s, ráfaga 20) y
        // el navegador veía `429` en imports de módulo → página en blanco, o
        // en el reload siguiente (burst todavía sin recargar) una página de
        // error genérica — no era un bug intermitente, era agotamiento del
        // limitador contra tráfico de assets estáticos, no de abuso real.
        .route_layer(GovernorLayer::new(governor_conf))
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
        .with_state(estado);

    capa_headers_seguridad(router)
}
