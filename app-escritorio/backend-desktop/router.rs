// Autor: Athan Espinoza

//! Router del modo escritorio — `/auth/*`, CRUD completo de `resources`
//! (crear/listar/obtener/editar/eliminar/mover/secret/recipients),
//! `folders`/`tags`, y los endpoints "vacíos" que el resto del Vault pide
//! sin bloquear (`/metadata-keys`, `/password-policy`, etc., ver
//! `metadata_keys_vacio` más abajo). Deliberadamente **no** reusa
//! `auth::handlers::*`/`resources::handlers::*`: esos handlers están
//! atados en compile-time a `axum::extract::State<crate::state::AppState>`
//! (el `AppState` de modo servidor) vía sus helpers privados `servicio()`,
//! que además hardcodean los tipos `Pg*Repository` en las variables de
//! tipo de cada `*Service` — no hay forma de reusarlos tal cual con un
//! `AppStateDesktop` distinto. Lo que SÍ se reusa 100%, sin duplicar nada
//! de lógica de negocio: `*::dto` (mismo contrato JSON que ya conoce el
//! frontend) y cada `*::service::*Service` (la Service en sí, ya
//! genérica). Esto es sólo la capa de Controller — extraer body, invocar
//! el Service, mapear a respuesta — reescrita para un `State` distinto,
//! exactamente lo que la arquitectura Controller→Service→Repository ya
//! separa.
//!
//! Fuera de alcance en este modo, a propósito (spec/13 §5, sin
//! `permissions`/otros usuarios): compartir un recurso/carpeta con otro
//! usuario o grupo (`/{id}/share`, `/share-bulk`, `/{id}/permissions*`,
//! `/{id}/leave`), `export`/`external_shares`/audit-lite (sin SQLite
//! todavía, ver spec/10-mapa-mental.md). También fuera de alcance:
//! `verify-email`/`resend` (el bootstrap siempre los saltea, spec/13 §16),
//! `logout`/`public_key`/`buscar`/`avatar` (necesitan el extractor
//! `AuthenticatedUser`, atado también a `AppState`).

use axum::extract::{Path, Query, State};
use axum::http::header::{self, HeaderMap};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use std::collections::HashSet;
use time::OffsetDateTime;
use tower_http::cors::{Any, AllowOrigin, CorsLayer};
use uuid::Uuid;

use crate::auth::dto::{
    ChallengeRequest, ChallengeResponse, KeyMaterialRequest, KeyMaterialResponse, RegisterRequest, RegisterResponse,
    ServerKeyResponse, VerifyDeviceRequest, VerifyRequest, VerifyResponse,
};
use crate::auth::models::{NuevoUsuario, ResultadoRegistro, ResultadoVerify};
use crate::auth::repository::{SessionRepository, UserRepository};
use crate::auth::service::AuthService;
use crate::b64;
use crate::error::{ApiError, DomainError, RepoError};
use crate::folders::dto::{CrearCarpetaRequest, MoverCarpetaRequest, NodoArbolResponse};
use crate::folders::repository::{FolderItemRepository, FolderRepository};
use crate::folders::service::FolderService;
use crate::resources::dto::{
    ActualizarRecursoRequest, CambiarTipoRecursoRequest, CrearRecursoRequest, DestinatarioResponse, ListarQuery,
    MoverRecursoRequest, RecursoResponse, SecretoResponse,
};
use crate::resources::models::EnvelopeInput;
use crate::resources::repository::ResourceTypeRepository;
use crate::resources::service::ResourceService;
use crate::tags::dto::{CrearTagRequest, TagResponse};
use crate::tags::models::Tag;
use crate::tags::service::TagService;

use super::origen;
use super::state::AppStateDesktop;

/// Mismo criterio que `auth::extractor::AuthenticatedUser`, para
/// `AppStateDesktop` — no reusable tal cual porque está atado en
/// compile-time a `axum::extract::State<crate::state::AppState>`. Sin
/// `security_stamp`/MFA acá (modo escritorio no monta esos endpoints
/// todavía) — sólo sesión no revocada/no vencida, igual que
/// `SessionRepository::validar_cualquiera`.
pub struct AuthenticatedUserDesktop {
    pub user_id: Uuid,
    pub session_id: Uuid,
}

impl axum::extract::FromRequestParts<AppStateDesktop> for AuthenticatedUserDesktop {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppStateDesktop) -> Result<Self, Self::Rejection> {
        let session_id: Uuid = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .and_then(|v| v.parse().ok())
            .ok_or(DomainError::InvalidCredentials)?;

        let user_id = state.sesiones.validar(session_id).await.map_err(DomainError::from)?.ok_or(DomainError::InvalidCredentials)?;
        Ok(AuthenticatedUserDesktop { user_id, session_id })
    }
}

#[allow(clippy::type_complexity)]
fn servicio(
    state: &AppStateDesktop,
) -> AuthService<
    '_,
    crate::desktop::repositories::auth::SqliteUserRepository,
    crate::desktop::repositories::auth::SqliteAuthChallengeRepository,
    crate::desktop::repositories::auth::SqliteSessionRepository,
    crate::desktop::repositories::auth::SqliteKnownDeviceRepository,
    crate::desktop::repositories::auth::SqliteDeviceChallengeRepository,
    crate::desktop::repositories::mfa::SqliteMfaPolicyRepository,
    crate::desktop::repositories::mfa::SqliteTotpCredentialRepository,
    crate::desktop::repositories::mfa::SqliteMfaChallengeRepository,
    crate::desktop::repositories::smtp_config::SqliteSmtpConfigRepository,
    crate::desktop::repositories::self_registration::SqliteSelfRegistrationPolicyRepository,
    crate::desktop::repositories::auth::SqliteUserRepository,
> {
    AuthService {
        usuarios: &state.usuarios,
        challenges: &state.challenges,
        sesiones: &state.sesiones,
        dispositivos: &state.dispositivos,
        desafios_dispositivo: &state.desafios_dispositivo,
        mfa_policy: &state.mfa_policy,
        mfa_totp: &state.mfa_totp,
        mfa_challenges: &state.mfa_challenges,
        smtp_config: &state.smtp_config,
        self_registration: &state.self_registration_policy,
        email_verification: &state.usuarios,
        eventos: state.eventos.clone(),
    }
}

/// Mismo mapeo que `auth::handlers::resultado_a_response` (privado ahí, no
/// reusable) — cinco estados posibles de F-02/F-14/F-16, sin duplicar
/// ninguna lógica de decisión, sólo el nombre del estado para JSON.
fn resultado_a_response(resultado: ResultadoVerify) -> VerifyResponse {
    match resultado {
        ResultadoVerify::SesionCompleta(sesion) => {
            VerifyResponse { estado: "completo", session_id: Some(sesion.id), user_id: Some(sesion.user_id), device_challenge_id: None }
        }
        ResultadoVerify::PendienteDispositivo { device_challenge_id } => {
            VerifyResponse { estado: "pendiente_dispositivo", session_id: None, user_id: None, device_challenge_id: Some(device_challenge_id) }
        }
        ResultadoVerify::PendienteMfa { session_id } => {
            VerifyResponse { estado: "pendiente_mfa", session_id: Some(session_id), user_id: None, device_challenge_id: None }
        }
        ResultadoVerify::RequiereConfigurarMfa { session_id } => {
            VerifyResponse { estado: "requiere_configurar_mfa", session_id: Some(session_id), user_id: None, device_challenge_id: None }
        }
        ResultadoVerify::RequiereCambiarPassphrase { session_id } => {
            VerifyResponse { estado: "requiere_cambiar_passphrase", session_id: Some(session_id), user_id: None, device_challenge_id: None }
        }
    }
}

/// F-46 (modo escritorio = 1 solo usuario, spec/13 §4/§5): rechazo explícito
/// de un segundo registro. Hasta el 2026-09-17 esto "andaba" por un efecto
/// colateral accidental — `SqliteSmtpConfigRepository::obtener` siempre
/// devuelve todos los campos en `None`, así que el chequeo genérico de
/// `AuthService::registrar` ("¿hay SMTP configurado?") rechazaba cualquier
/// registro después del primero por esa razón, con un mensaje que no
/// explica la causa real ("SMTP no configurado", no "esta bóveda ya tiene
/// un usuario"). Frágil además: `SqliteSelfRegistrationPolicyRepository`
/// TAMBIÉN es un stub que siempre devuelve `enabled: true` sin importar qué
/// se guarde — si algún día alguno de los dos stubs se conecta de verdad,
/// esta protección accidental desaparece sola. Chequeo explícito acá,
/// antes de tocar nada más.
async fn register(
    State(state): State<AppStateDesktop>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, ApiError> {
    if state.usuarios.existe_alguno().await.map_err(DomainError::from)? {
        return Err(DomainError::ValidacionInvalida(
            "esta bóveda de escritorio ya tiene un usuario — el modo escritorio es de un solo usuario, no se pueden crear más".into(),
        )
        .into());
    }

    let publica_x25519 = b64::decode(&req.public_key_x25519_b64)
        .map_err(|_| DomainError::ValidacionInvalida("public_key_x25519_b64 inválido".into()))?;
    let publica_ed25519 = b64::decode(&req.public_key_ed25519_b64)
        .map_err(|_| DomainError::ValidacionInvalida("public_key_ed25519_b64 inválido".into()))?;
    let blob = b64::decode(&req.encrypted_private_key_blob_b64)
        .map_err(|_| DomainError::ValidacionInvalida("encrypted_private_key_blob_b64 inválido".into()))?;
    let nonce = b64::decode(&req.private_key_nonce_b64)
        .map_err(|_| DomainError::ValidacionInvalida("private_key_nonce_b64 inválido".into()))?;
    let salt = b64::decode(&req.kdf_salt_b64)
        .map_err(|_| DomainError::ValidacionInvalida("kdf_salt_b64 inválido".into()))?;

    let nuevo = NuevoUsuario {
        email: &req.email,
        display_name: &req.display_name,
        public_key_x25519: &publica_x25519,
        public_key_ed25519: &publica_ed25519,
        encrypted_private_key_blob: &blob,
        private_key_nonce: &nonce,
        kdf_salt: &salt,
    };

    let resultado = servicio(&state).registrar(nuevo).await?;
    let (user_id, pending_verification) = match resultado {
        ResultadoRegistro::Completo(usuario) => (usuario.id, false),
        ResultadoRegistro::PendienteVerificacion { user_id } => (user_id, true),
    };
    Ok(Json(RegisterResponse { user_id, pending_verification }))
}

async fn server_key(State(state): State<AppStateDesktop>) -> Json<ServerKeyResponse> {
    Json(ServerKeyResponse { public_key_ed25519_b64: b64::encode(state.server_public_key_ed25519.as_slice()) })
}

/// F-46 (2026-09-17, pedido del usuario tras probar la ventana real):
/// endpoint público sin auth — el login de escritorio lo usa para esconder
/// el link "Registrate" una vez que ya existe el único usuario de esta
/// bóveda (mostrarlo siempre era confuso: iba a fallar seguro después del
/// primer alta, con el rechazo explícito de `register` de más arriba).
/// Sólo existe en el router de escritorio — en modo servidor "¿existe algún
/// usuario?" no tiene ningún uso de UI y sería una fuga de información
/// gratuita sobre una instancia multiusuario.
#[derive(serde::Serialize)]
struct ExisteUsuarioResponse {
    existe: bool,
}

async fn existe_usuario(State(state): State<AppStateDesktop>) -> Result<Json<ExisteUsuarioResponse>, ApiError> {
    let existe = state.usuarios.existe_alguno().await.map_err(DomainError::from)?;
    Ok(Json(ExisteUsuarioResponse { existe }))
}

/// Rechaza (403) lo que no venga de un `Origin` ni de un `Host` permitidos —
/// ver `origen.rs` (páginas web ajenas y DNS rebinding).
async fn guardia_origen_y_host(req: axum::extract::Request, next: Next) -> Response {
    let cabeceras = req.headers();
    let host_ok = cabeceras.get(header::HOST).is_none_or(|h| h.to_str().is_ok_and(origen::host_permitido));
    let origen_ok = cabeceras.get(header::ORIGIN).is_none_or(|o| o.to_str().is_ok_and(origen::origen_permitido));
    if host_ok && origen_ok {
        return next.run(req).await;
    }
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({ "error": { "code": "FORBIDDEN_ORIGIN", "message": "origen no permitido" } })),
    )
        .into_response()
}

/// Un fallo de E/S (copias de seguridad) como error interno: al cliente sólo
/// le llega "error interno", el detalle queda en el log.
fn interno(e: anyhow::Error) -> DomainError {
    tracing::error!(error = %format!("{e:#}"), "fallo interno en el backend local");
    DomainError::Interno(RepoError::Database(sqlx::Error::Io(std::io::Error::other(e.to_string()))))
}

#[derive(serde::Serialize)]
struct RespaldosResponse {
    /// Carpeta donde quedan las copias (`<datadir>/backups`).
    carpeta: String,
    respaldos: Vec<super::respaldos::Respaldo>,
}

fn respaldos_response(datadir: &std::path::Path) -> Result<RespaldosResponse, ApiError> {
    let respaldos = super::respaldos::listar(datadir).map_err(interno)?;
    Ok(RespaldosResponse { carpeta: super::respaldos::carpeta_de_respaldos(datadir).to_string_lossy().into_owned(), respaldos })
}

/// Copias de seguridad de la bóveda (F-53): las que hizo la app antes de
/// migrar y las que pidió el usuario.
async fn listar_respaldos(State(state): State<AppStateDesktop>, _auth: AuthenticatedUserDesktop) -> Result<Json<RespaldosResponse>, ApiError> {
    Ok(Json(respaldos_response(&state.datadir)?))
}

/// "Crear copia ahora": copia consistente de la bóveda, cifrada igual que
/// ella, en la carpeta de copias.
async fn crear_respaldo(State(state): State<AppStateDesktop>, _auth: AuthenticatedUserDesktop) -> Result<Json<RespaldosResponse>, ApiError> {
    super::respaldos::respaldar(&state.pool, &state.datadir, super::respaldos::PREFIJO_MANUAL, "")
        .await
        .map_err(interno)?;
    Ok(Json(respaldos_response(&state.datadir)?))
}

/// Cierra la sesión en el backend local: sin esto, "cerrar sesión" sólo
/// olvidaba el token del lado del cliente y la sesión seguía válida hasta
/// vencer por TTL.
async fn logout_local(State(state): State<AppStateDesktop>, auth: AuthenticatedUserDesktop) -> Result<(), ApiError> {
    servicio(&state).logout(auth.session_id, auth.user_id).await?;
    Ok(())
}

async fn challenge(
    State(state): State<AppStateDesktop>,
    Json(req): Json<ChallengeRequest>,
) -> Result<Json<ChallengeResponse>, ApiError> {
    let nonce = servicio(&state).challenge(&req.email).await?;
    Ok(Json(ChallengeResponse { nonce_b64: b64::encode(&nonce) }))
}

async fn key_material(
    State(state): State<AppStateDesktop>,
    Json(req): Json<KeyMaterialRequest>,
) -> Result<Json<KeyMaterialResponse>, ApiError> {
    let material = servicio(&state).material_desbloqueo(&req.email).await?;
    Ok(Json(KeyMaterialResponse {
        encrypted_private_key_blob_b64: b64::encode(&material.encrypted_private_key_blob),
        private_key_nonce_b64: b64::encode(&material.private_key_nonce),
        kdf_salt_b64: b64::encode(&material.kdf_salt),
    }))
}

async fn verify(
    State(state): State<AppStateDesktop>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, ApiError> {
    let nonce =
        b64::decode(&req.nonce_b64).map_err(|_| DomainError::ValidacionInvalida("nonce_b64 inválido".into()))?;
    let firma = b64::decode(&req.signature_b64)
        .map_err(|_| DomainError::ValidacionInvalida("signature_b64 inválido".into()))?;
    let device_token_hash = b64::decode(&req.device_token_hash_b64)
        .map_err(|_| DomainError::ValidacionInvalida("device_token_hash_b64 inválido".into()))?;

    let resultado = servicio(&state).verify(&req.email, &nonce, &firma, &device_token_hash, req.force_mfa).await?;
    Ok(Json(resultado_a_response(resultado)))
}

async fn verify_device(
    State(state): State<AppStateDesktop>,
    Json(req): Json<VerifyDeviceRequest>,
) -> Result<Json<VerifyResponse>, ApiError> {
    let resultado = servicio(&state).verify_device(req.device_challenge_id, &req.code).await?;
    Ok(Json(resultado_a_response(resultado)))
}

#[allow(clippy::type_complexity)]
fn servicio_recursos(
    state: &AppStateDesktop,
) -> ResourceService<
    '_,
    crate::desktop::repositories::resources::SqliteResourceRepository,
    crate::desktop::repositories::resources::SqliteSecretEnvelopeRepository,
    crate::desktop::repositories::resources::SqlitePermissionRepository,
    crate::desktop::repositories::resources::SqliteResourceTypeRepository,
    crate::desktop::repositories::folders::SqliteFolderItemRepository,
    crate::desktop::repositories::groups::SqliteGroupMemberRepository,
    crate::desktop::repositories::admin::SqliteRoleRepository,
> {
    ResourceService {
        recursos: &state.recursos,
        envolturas: &state.envolturas,
        permisos: &state.permisos,
        tipos_recurso: &state.tipos_recurso,
        items: &state.items_de_carpeta,
        grupos: &state.miembros_de_grupo,
        roles: &state.roles,
        eventos: state.eventos.clone(),
    }
}

#[allow(clippy::type_complexity)]
fn servicio_carpetas(
    state: &AppStateDesktop,
) -> FolderService<
    '_,
    crate::desktop::repositories::folders::SqliteFolderRepository,
    crate::desktop::repositories::folders::SqliteFolderItemRepository,
    crate::desktop::repositories::resources::SqlitePermissionRepository,
    crate::desktop::repositories::groups::SqliteGroupMemberRepository,
    crate::desktop::repositories::admin::SqliteRoleRepository,
> {
    FolderService {
        carpetas: &state.carpetas,
        items: &state.items_de_carpeta,
        permisos: &state.permisos,
        grupos: &state.miembros_de_grupo,
        roles: &state.roles,
    }
}

#[allow(clippy::type_complexity)]
fn servicio_tags(
    state: &AppStateDesktop,
) -> TagService<'_, crate::desktop::repositories::tags::SqliteTagRepository, crate::desktop::repositories::resources::SqlitePermissionRepository>
{
    TagService { tags: &state.tags, permisos: &state.permisos }
}

fn tag_a_response(tag: Tag) -> TagResponse {
    TagResponse { id: tag.id, name: tag.name, is_shared: tag.is_shared, created_by: tag.created_by }
}

fn recurso_a_response(recurso: crate::resources::models::Resource, resource_type_slug: String) -> RecursoResponse {
    RecursoResponse {
        id: recurso.id,
        resource_type_id: recurso.resource_type_id,
        resource_type_slug,
        metadata_ciphertext_b64: b64::encode(&recurso.metadata_ciphertext),
        metadata_nonce_b64: b64::encode(&recurso.metadata_nonce),
        created_by: recurso.created_by,
        created_at: recurso.created_at,
        updated_at: recurso.updated_at,
        metadata_key_type: recurso.metadata_key_type,
        metadata_key_id: recurso.metadata_key_id,
        folder_id: None,
        // Modo escritorio: dueño único, siempre puede borrar lo suyo — sin
        // el camino de "admin de grupo" de la versión servidor.
        puede_borrar: true,
    }
}

/// `POST /resources` — sólo `resource_type_slug` ya sembrado
/// (`login-password`, spec/13 §5) y sin `metadata_key_id` (siempre
/// `user_key` en este modo, spec/13 §5).
async fn crear_recurso(
    State(state): State<AppStateDesktop>,
    auth: AuthenticatedUserDesktop,
    Json(req): Json<CrearRecursoRequest>,
) -> Result<Json<RecursoResponse>, ApiError> {
    let resource_type_id = state
        .tipos_recurso
        .id_por_slug(&req.resource_type_slug)
        .await
        .map_err(DomainError::from)?
        .ok_or_else(|| DomainError::ValidacionInvalida("resource_type_slug desconocido".into()))?;

    let metadata_ciphertext = b64::decode(&req.metadata_ciphertext_b64)
        .map_err(|_| DomainError::ValidacionInvalida("metadata_ciphertext_b64 inválido".into()))?;
    let metadata_nonce = b64::decode(&req.metadata_nonce_b64)
        .map_err(|_| DomainError::ValidacionInvalida("metadata_nonce_b64 inválido".into()))?;
    let sealed_dek = b64::decode(&req.sealed_dek_b64)
        .map_err(|_| DomainError::ValidacionInvalida("sealed_dek_b64 inválido".into()))?;
    let secret_ciphertext = b64::decode(&req.secret_ciphertext_b64)
        .map_err(|_| DomainError::ValidacionInvalida("secret_ciphertext_b64 inválido".into()))?;
    let secret_nonce = b64::decode(&req.secret_nonce_b64)
        .map_err(|_| DomainError::ValidacionInvalida("secret_nonce_b64 inválido".into()))?;

    let recurso = servicio_recursos(&state)
        .crear(
            req.id,
            resource_type_id,
            &metadata_ciphertext,
            &metadata_nonce,
            auth.user_id,
            &sealed_dek,
            &secret_ciphertext,
            &secret_nonce,
            None,
        )
        .await?;

    Ok(Json(recurso_a_response(recurso, req.resource_type_slug)))
}

/// `GET /resources?tag_id=&folder_id=&incluir_subcarpetas=` — mismo criterio
/// que `resources::handlers::listar` (modo servidor): `tag_id` filtra contra
/// `TagService::recursos_por_tag`, `folder_id` contra el mapa de posiciones
/// de `folder_items` (con `incluir_subcarpetas` sumando los descendientes vía
/// `FolderRepository::descendientes_de`). `folder_id` en la respuesta se
/// calcula siempre (no sólo cuando filtra) — la UI lo necesita para
/// mostrar/mover cada recurso sin una consulta aparte por fila.
async fn listar_recursos(
    State(state): State<AppStateDesktop>,
    auth: AuthenticatedUserDesktop,
    Query(q): Query<ListarQuery>,
) -> Result<Json<Vec<RecursoResponse>>, ApiError> {
    let recursos = servicio_recursos(&state).listar_visibles(auth.user_id).await?;

    let recursos = match q.tag_id {
        None => recursos,
        Some(tag_id) => {
            let ids_con_tag: HashSet<Uuid> = servicio_tags(&state).recursos_por_tag(auth.user_id, tag_id).await?.into_iter().collect();
            recursos.into_iter().filter(|r| ids_con_tag.contains(&r.id)).collect()
        }
    };

    let posiciones = state.items_de_carpeta.posiciones_de_recursos(auth.user_id).await.map_err(DomainError::from)?;
    let slugs = state.tipos_recurso.mapa_id_a_slug().await.map_err(DomainError::from)?;

    let mut respuesta = Vec::with_capacity(recursos.len());
    for r in recursos {
        let slug = slugs.get(&r.resource_type_id).cloned().unwrap_or_default();
        let mut resp = recurso_a_response(r, slug);
        resp.folder_id = posiciones.get(&resp.id).copied();
        respuesta.push(resp);
    }

    let respuesta = match q.folder_id {
        None => respuesta,
        Some(folder_id) => {
            let carpetas_validas: HashSet<Uuid> = if q.incluir_subcarpetas {
                let mut set: HashSet<Uuid> =
                    state.carpetas.descendientes_de(auth.user_id, folder_id).await.map_err(DomainError::from)?.into_iter().collect();
                set.insert(folder_id);
                set
            } else {
                std::iter::once(folder_id).collect()
            };
            respuesta.into_iter().filter(|r| r.folder_id.is_some_and(|f| carpetas_validas.contains(&f))).collect()
        }
    };

    Ok(Json(respuesta))
}

/// `PUT /resources/{id}/move` (F-11) — misma lógica que la versión servidor
/// (`FolderService::mover_recurso`), construida con los repos SQLite.
async fn mover_recurso(
    State(state): State<AppStateDesktop>,
    auth: AuthenticatedUserDesktop,
    Path(resource_id): Path<Uuid>,
    Json(req): Json<MoverRecursoRequest>,
) -> Result<(), ApiError> {
    servicio_carpetas(&state).mover_recurso(auth.user_id, resource_id, req.folder_id).await?;
    Ok(())
}

/// `POST /folders` (F-09).
async fn crear_carpeta(
    State(state): State<AppStateDesktop>,
    auth: AuthenticatedUserDesktop,
    Json(req): Json<CrearCarpetaRequest>,
) -> Result<Json<NodoArbolResponse>, ApiError> {
    let name_ciphertext = b64::decode(&req.name_ciphertext_b64)
        .map_err(|_| DomainError::ValidacionInvalida("name_ciphertext_b64 inválido".into()))?;
    let name_nonce =
        b64::decode(&req.name_nonce_b64).map_err(|_| DomainError::ValidacionInvalida("name_nonce_b64 inválido".into()))?;

    let carpeta = servicio_carpetas(&state).crear(auth.user_id, req.id, &name_ciphertext, &name_nonce, req.parent_folder_id).await?;

    Ok(Json(NodoArbolResponse {
        folder_id: carpeta.id,
        parent_folder_id: req.parent_folder_id,
        name_ciphertext_b64: req.name_ciphertext_b64,
        name_nonce_b64: req.name_nonce_b64,
        group_id: None,
    }))
}

/// `GET /folders` — sin `group_id` real (siempre `None`, spec/13 §5: sin
/// grupos en este modo, ninguna carpeta puede estar compartida con uno).
async fn listar_carpetas(State(state): State<AppStateDesktop>, auth: AuthenticatedUserDesktop) -> Result<Json<Vec<NodoArbolResponse>>, ApiError> {
    let arbol = servicio_carpetas(&state).listar_arbol(auth.user_id).await?;
    Ok(Json(
        arbol
            .into_iter()
            .map(|n| NodoArbolResponse {
                folder_id: n.folder_id,
                parent_folder_id: n.parent_folder_id,
                name_ciphertext_b64: b64::encode(&n.name_ciphertext),
                name_nonce_b64: b64::encode(&n.name_nonce),
                group_id: None,
            })
            .collect(),
    ))
}

/// `PUT /folders/{id}/move` (F-09) — reposiciona sólo en el árbol propio,
/// nunca toca la vista de otro usuario (no aplica en este modo de todos
/// modos: sólo hay un usuario).
async fn mover_carpeta(
    State(state): State<AppStateDesktop>,
    auth: AuthenticatedUserDesktop,
    Path(folder_id): Path<Uuid>,
    Json(req): Json<MoverCarpetaRequest>,
) -> Result<(), ApiError> {
    servicio_carpetas(&state).mover(auth.user_id, folder_id, req.new_parent_folder_id).await?;
    Ok(())
}

/// `DELETE /folders/{id}` (F-47) — sólo carpetas vacías, ver
/// `FolderService::eliminar`.
async fn eliminar_carpeta(
    State(state): State<AppStateDesktop>,
    auth: AuthenticatedUserDesktop,
    Path(folder_id): Path<Uuid>,
) -> Result<(), ApiError> {
    servicio_carpetas(&state).eliminar(auth.user_id, folder_id).await?;
    Ok(())
}

/// `GET /tags`.
async fn listar_tags(State(state): State<AppStateDesktop>, auth: AuthenticatedUserDesktop) -> Result<Json<Vec<TagResponse>>, ApiError> {
    let tags = servicio_tags(&state).listar_disponibles(auth.user_id).await?;
    Ok(Json(tags.into_iter().map(tag_a_response).collect()))
}

/// `POST /tags` — modo escritorio sin RBAC organizacional (spec/13 §16): el
/// único usuario local no necesita "ser admin" para crear un tag `is_shared`
/// (esa columna nunca tiene efecto real en este modo, spec/13 §5, pero se
/// acepta el valor pedido en vez de rechazarlo con un concepto — "admin" —
/// que no existe acá).
async fn crear_tag(
    State(state): State<AppStateDesktop>,
    auth: AuthenticatedUserDesktop,
    Json(req): Json<CrearTagRequest>,
) -> Result<Json<TagResponse>, ApiError> {
    let tag = servicio_tags(&state).crear(auth.user_id, true, req.id, &req.name, req.is_shared).await?;
    Ok(Json(tag_a_response(tag)))
}

/// `DELETE /tags/{id}` (F-47) — modo escritorio sin RBAC (spec/13 §16): el
/// único usuario local siempre puede borrar sus propios tags, `is_shared`
/// nunca aplica en este modo (spec/13 §5) así que `es_admin` da igual el
/// valor que reciba `TagService::eliminar` para ese caso.
async fn eliminar_tag(
    State(state): State<AppStateDesktop>,
    auth: AuthenticatedUserDesktop,
    Path(tag_id): Path<Uuid>,
) -> Result<(), ApiError> {
    servicio_tags(&state).eliminar(auth.user_id, true, tag_id).await?;
    Ok(())
}

/// `POST /resources/{resource_id}/tags/{tag_id}`.
async fn aplicar_tag(
    State(state): State<AppStateDesktop>,
    auth: AuthenticatedUserDesktop,
    Path((resource_id, tag_id)): Path<(Uuid, Uuid)>,
) -> Result<(), ApiError> {
    servicio_tags(&state).aplicar(auth.user_id, resource_id, tag_id).await?;
    Ok(())
}

/// `DELETE /resources/{resource_id}/tags/{tag_id}`.
async fn quitar_tag(
    State(state): State<AppStateDesktop>,
    auth: AuthenticatedUserDesktop,
    Path((resource_id, tag_id)): Path<(Uuid, Uuid)>,
) -> Result<(), ApiError> {
    servicio_tags(&state).quitar(auth.user_id, resource_id, tag_id).await?;
    Ok(())
}

async fn obtener_recurso(
    State(state): State<AppStateDesktop>,
    auth: AuthenticatedUserDesktop,
    Path(resource_id): Path<Uuid>,
) -> Result<Json<RecursoResponse>, ApiError> {
    let recurso = servicio_recursos(&state).obtener(resource_id, auth.user_id).await?;
    let slug = state
        .tipos_recurso
        .mapa_id_a_slug()
        .await
        .map_err(DomainError::from)?
        .get(&recurso.resource_type_id)
        .cloned()
        .unwrap_or_default();
    Ok(Json(recurso_a_response(recurso, slug)))
}

async fn obtener_secreto(
    State(state): State<AppStateDesktop>,
    auth: AuthenticatedUserDesktop,
    Path(resource_id): Path<Uuid>,
) -> Result<Json<SecretoResponse>, ApiError> {
    let envelope = servicio_recursos(&state).obtener_secreto(resource_id, auth.user_id).await?;
    Ok(Json(SecretoResponse {
        sealed_dek_b64: b64::encode(&envelope.sealed_dek),
        secret_ciphertext_b64: b64::encode(&envelope.secret_ciphertext),
        secret_nonce_b64: b64::encode(&envelope.secret_nonce),
    }))
}

/// `GET /resources/{id}/recipients` (F-07) — el editor lo pide primero
/// para saber a quién re-sellar la DEK nueva antes del `PUT`. En modo
/// escritorio siempre hay exactamente 1 destinatario (uno mismo).
async fn recipients(
    State(state): State<AppStateDesktop>,
    auth: AuthenticatedUserDesktop,
    Path(resource_id): Path<Uuid>,
) -> Result<Json<Vec<DestinatarioResponse>>, ApiError> {
    let destinatarios = servicio_recursos(&state).listar_destinatarios(resource_id, auth.user_id).await?;
    Ok(Json(
        destinatarios
            .into_iter()
            .map(|d| DestinatarioResponse { user_id: d.user_id, public_key_x25519_b64: b64::encode(&d.public_key_x25519) })
            .collect(),
    ))
}

/// `PUT /resources/{id}` (F-07) — bug real encontrado probando en la
/// ventana real (2026-09-16): faltaba por completo en este router, editar
/// cualquier recurso devolvía 404. Misma concurrencia optimista real vía
/// `If-Match` que la versión servidor.
async fn editar_recurso(
    State(state): State<AppStateDesktop>,
    auth: AuthenticatedUserDesktop,
    Path(resource_id): Path<Uuid>,
    headers: HeaderMap,
    Json(req): Json<ActualizarRecursoRequest>,
) -> Result<Json<RecursoResponse>, ApiError> {
    let if_match = headers
        .get("if-match")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| DomainError::ValidacionInvalida("falta el header If-Match".into()))?;
    let expected_updated_at = OffsetDateTime::parse(if_match, &time::format_description::well_known::Rfc3339)
        .map_err(|_| DomainError::ValidacionInvalida("If-Match debe ser una fecha RFC3339 válida".into()))?;

    let metadata_ciphertext = b64::decode(&req.metadata_ciphertext_b64)
        .map_err(|_| DomainError::ValidacionInvalida("metadata_ciphertext_b64 inválido".into()))?;
    let metadata_nonce = b64::decode(&req.metadata_nonce_b64)
        .map_err(|_| DomainError::ValidacionInvalida("metadata_nonce_b64 inválido".into()))?;

    let mut envelopes = Vec::with_capacity(req.envelopes.len());
    for e in req.envelopes {
        envelopes.push(EnvelopeInput {
            user_id: e.recipient_user_id,
            sealed_dek: b64::decode(&e.sealed_dek_b64).map_err(|_| DomainError::ValidacionInvalida("sealed_dek_b64 inválido".into()))?,
            secret_ciphertext: b64::decode(&e.secret_ciphertext_b64)
                .map_err(|_| DomainError::ValidacionInvalida("secret_ciphertext_b64 inválido".into()))?,
            secret_nonce: b64::decode(&e.secret_nonce_b64)
                .map_err(|_| DomainError::ValidacionInvalida("secret_nonce_b64 inválido".into()))?,
        });
    }

    let recurso = servicio_recursos(&state)
        .editar(resource_id, auth.user_id, expected_updated_at, &metadata_ciphertext, &metadata_nonce, envelopes)
        .await?;
    let slug = state.tipos_recurso.mapa_id_a_slug().await.map_err(DomainError::from)?.get(&recurso.resource_type_id).cloned().unwrap_or_default();
    Ok(Json(recurso_a_response(recurso, slug)))
}

/// `PUT /resources/{id}/type` (2026-09-17) — mismo `ResourceService::cambiar_tipo`
/// que la versión servidor, ver ese archivo para el detalle de por qué sólo
/// se permite entre tipos con el mismo `json_schema`.
async fn cambiar_tipo_recurso(
    State(state): State<AppStateDesktop>,
    auth: AuthenticatedUserDesktop,
    Path(resource_id): Path<Uuid>,
    Json(req): Json<CambiarTipoRecursoRequest>,
) -> Result<Json<RecursoResponse>, ApiError> {
    let recurso = servicio_recursos(&state).cambiar_tipo(resource_id, auth.user_id, &req.resource_type_slug).await?;
    Ok(Json(recurso_a_response(recurso, req.resource_type_slug)))
}

/// `DELETE /resources/{id}` — bug real encontrado en la misma ventana:
/// faltaba también, borrar cualquier recurso devolvía 404. En este modo
/// `ResourceService::eliminar` no exige nada más allá de que el recurso
/// exista (el único usuario local es dueño de todo, ver el fix de
/// `usuario_tiene_permiso` en `repositories/admin.rs`).
async fn eliminar_recurso(
    State(state): State<AppStateDesktop>,
    auth: AuthenticatedUserDesktop,
    Path(resource_id): Path<Uuid>,
) -> Result<(), ApiError> {
    servicio_recursos(&state).eliminar(resource_id, auth.user_id).await?;
    Ok(())
}

/// La carga del Vault pide además `/metadata-keys`/`/password-policy`
/// (hallazgo real probando en vivo: `crearRecurso`/`listarRecursos` llaman
/// primero a `GET /metadata-keys` — sin este endpoint devolvía 404 y
/// abortaba TODO antes de llegar a `/resources`). `metadata_keys` no se
/// porta a SQLite en este modo (spec/13 §4/§5: sin metadata compartida con 1
/// solo usuario) — la respuesta correcta es "no hay nada": lista vacía.
/// `/folders`/`/tags` migraron a SQLite real el 2026-09-16 (ver
/// `crear_carpeta`/`listar_carpetas`/`crear_tag`/`listar_tags` más abajo).
async fn metadata_keys_vacio() -> Json<Vec<serde_json::Value>> {
    Json(Vec::new())
}

/// `GET /me` — el layout de `(app)` lo pide siempre (nombre/email en el pie
/// del nav). No reusa `me::handlers::perfil` (depende de `PerfilRepository`,
/// módulo `me` sin migrar) — arma la respuesta directo desde lo que
/// `auth::repository::UserRepository` ya expone, sin abrir un módulo nuevo
/// sólo para esto. `role` fijo en `"user"` (vestigial, sin RBAC en este modo).
async fn me_perfil(State(state): State<AppStateDesktop>, auth: AuthenticatedUserDesktop) -> Result<Json<serde_json::Value>, ApiError> {
    let (email, display_name) = state.usuarios.email_y_nombre(auth.user_id).await.map_err(DomainError::from)?.ok_or(DomainError::NotFound)?;
    let usuario = state.usuarios.buscar_por_id(auth.user_id).await.map_err(DomainError::from)?.ok_or(DomainError::NotFound)?;
    let creado = fmt_dt_json(usuario.created_at);
    Ok(Json(serde_json::json!({
        "id": auth.user_id,
        "email": email,
        "display_name": display_name,
        "role": "user",
        "created_at": creado,
        "updated_at": creado,
        "keys_created_at": creado,
    })))
}

/// `GET /me/permissions` — modo escritorio sin RBAC organizacional (spec/13
/// §16), pero el único usuario local SÍ necesita los permisos granulares
/// que la propia UI del Vault chequea para gatear acciones sobre SU PROPIA
/// bóveda (exportar/importar/carpetas/revelar-contraseña/copiar) — sin
/// `'*'` a propósito (eso activaría el nav de admin, que no existe en este
/// modo). Nota: diverge de `SqliteRoleRepository::permisos_de_usuario`
/// (vacío) porque ese repo modela permisos de ROL/RBAC — acá se listan
/// directo los que la UI necesita, sin ese concepto de por medio.
async fn me_permisos() -> Json<Vec<String>> {
    Json(vec![
        "export.use".to_string(),
        "import.use".to_string(),
        "folders.use".to_string(),
        "folder.share".to_string(),
        "password.preview".to_string(),
        "password.copy".to_string(),
    ])
}

fn fmt_dt_json(dt: OffsetDateTime) -> String {
    dt.format(&time::format_description::well_known::Rfc3339).expect("formato de fecha válido")
}

/// `GET/PUT /me/preferences` — el layout las pide siempre para pisar el
/// default local (F-30/F-31/F-39). Sin tabla en este modo todavía: `GET`
/// devuelve un default fijo, `PUT` acepta y devuelve eco de lo que mandó el
/// cliente (no persiste entre reinicios — limitación conocida, no bloquea
/// el uso normal dentro de una misma sesión de la app).
async fn preferencias_default() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "locale": "es",
        "theme": "dark",
        "clipboard_clear_minutes": 30,
        "auto_lock_minutes": null,
    }))
}

async fn preferencias_actualizar(Json(req): Json<serde_json::Value>) -> Json<serde_json::Value> {
    Json(req)
}

/// `GET /export-policy` — modo escritorio: siempre habilitado, no hay
/// "organización" que lo restrinja (F-27 es justo el mecanismo de
/// backup/migrar de máquina que este modo necesita). `POST /export-events`
/// es el gate real que el cliente reporta antes de exportar/importar — en
/// este modo no hay nada que auditar a nivel de política, se acepta y listo.
async fn export_policy_default() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "export_enabled": true,
        "allowed_formats": ["kdbx", "csv", "cxf"],
        "import_enabled": true,
    }))
}

async fn export_events_noop(Json(_evento): Json<serde_json::Value>) -> axum::http::StatusCode {
    axum::http::StatusCode::OK
}

/// `GET /me/groups` — modo escritorio sin grupos (spec/13 §16), siempre
/// vacío.
async fn me_grupos() -> Json<Vec<serde_json::Value>> {
    Json(Vec::new())
}

/// `GET /me/avatar` — `404` real es la respuesta correcta acá (mismo
/// criterio que la versión servidor: "sin avatar" es un 404, no un `200`
/// vacío) — el frontend ya lo maneja (`obtenerAvatarUrl` trata `404` como
/// "no hay avatar", no como error). No hace falta un handler nuevo.
///
/// `GET /admin/password-policy` — mismos defaults que `/password-policy`
/// (sin distinción admin/no-admin en un solo usuario).
async fn admin_password_policy_default() -> Json<serde_json::Value> {
    password_policy_default().await
}

/// `GET /external-share-policy` — F-26 (external share) sigue disponible en
/// modo escritorio (compartir un secreto puntual por link no depende de más
/// usuarios internos, spec/13 §5) — pero como el módulo `external_shares`
/// no está migrado a SQLite todavía, se deja deshabilitado explícitamente
/// (no un 404) para que la UI lo trate como "política real, apagada" en vez
/// de "no se pudo consultar".
async fn external_share_policy_default() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "enabled": false,
        "allow_link": false,
        "allow_file": false,
        "max_expiration_hours": 24,
        "require_password": true,
    }))
}

async fn password_policy_default() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "min_passphrase_length": 12,
        "min_passphrase_entropy_bits": 60,
        "passphrase_rotation_days": null,
        "generator_default_length": 20,
        "generator_charset_rules": {"uppercase": true, "lowercase": true, "digits": true, "symbols": true, "exclude_ambiguous": true},
        "max_clipboard_clear_minutes": null,
        "max_auto_lock_minutes": null,
    }))
}

// ---------------------------------------------------------------------------
// Fase 3.3 (F-48 & F-47): Modos de persistencia y sincronización diferencial
// ---------------------------------------------------------------------------

use crate::desktop::{cargar_config, guardar_config, ModoPersistencia};

#[derive(serde::Serialize, serde::Deserialize)]
pub struct PersistenciaResponse {
    pub mode: ModoPersistencia,
}

#[derive(serde::Deserialize)]
pub struct CambiarPersistenciaRequest {
    pub mode: ModoPersistencia,
}

use crate::resources::repository::ResourceRepository;

fn db_err(e: sqlx::Error) -> ApiError {
    DomainError::from(RepoError::Database(e)).into()
}

fn io_api_err(msg: impl ToString) -> ApiError {
    DomainError::from(RepoError::Database(sqlx::Error::Io(std::io::Error::other(msg.to_string())))).into()
}

async fn obtener_persistencia(
    State(state): State<AppStateDesktop>,
    _usuario: AuthenticatedUserDesktop,
) -> Result<Json<PersistenciaResponse>, ApiError> {
    let config = cargar_config(&state.datadir).map_err(io_api_err)?;
    Ok(Json(PersistenciaResponse { mode: config.modo_persistencia }))
}

async fn cambiar_persistencia(
    State(state): State<AppStateDesktop>,
    _usuario: AuthenticatedUserDesktop,
    Json(payload): Json<CambiarPersistenciaRequest>,
) -> Result<Json<PersistenciaResponse>, ApiError> {
    let mut config = cargar_config(&state.datadir).map_err(io_api_err)?;
    config.modo_persistencia = payload.mode;
    guardar_config(&state.datadir, &config).map_err(io_api_err)?;
    Ok(Json(PersistenciaResponse { mode: config.modo_persistencia }))
}

// ---------------------------------------------------------------------------
// F-48 (modos `Memory`/`NamesOnly`): variantes "sólo metadata" de crear/editar
// un recurso, para cuando `sincronizarAhora()` (frontend) trae un recurso del
// servidor remoto y el modo activo pide NO replicar el cuerpo del secreto en
// disco local. El DEK sellado sí se guarda (aparte, en `metadata_deks`) —
// hace falta para descifrar la metadata offline, que sigue viviendo en la BD
// local en los 3 modos (spec/13 §8). Nunca se registra en el router de modo
// servidor: es un concepto exclusivo de la réplica local de escritorio.
// ---------------------------------------------------------------------------

use crate::resources::models::NivelPermiso;
use crate::resources::repository::PermissionRepository;

#[derive(serde::Deserialize)]
pub struct CrearRecursoMetadataOnlyRequest {
    pub id: Uuid,
    pub resource_type_slug: String,
    pub metadata_ciphertext_b64: String,
    pub metadata_nonce_b64: String,
    pub sealed_dek_b64: String,
    #[serde(default)]
    pub metadata_key_id: Option<Uuid>,
}

async fn crear_recurso_metadata_only(
    State(state): State<AppStateDesktop>,
    auth: AuthenticatedUserDesktop,
    Json(req): Json<CrearRecursoMetadataOnlyRequest>,
) -> Result<Json<RecursoResponse>, ApiError> {
    let resource_type_id = state
        .tipos_recurso
        .id_por_slug(&req.resource_type_slug)
        .await
        .map_err(DomainError::from)?
        .ok_or_else(|| DomainError::ValidacionInvalida("resource_type_slug desconocido".into()))?;

    let metadata_ciphertext = b64::decode(&req.metadata_ciphertext_b64)
        .map_err(|_| DomainError::ValidacionInvalida("metadata_ciphertext_b64 inválido".into()))?;
    let metadata_nonce = b64::decode(&req.metadata_nonce_b64)
        .map_err(|_| DomainError::ValidacionInvalida("metadata_nonce_b64 inválido".into()))?;
    let sealed_dek = b64::decode(&req.sealed_dek_b64)
        .map_err(|_| DomainError::ValidacionInvalida("sealed_dek_b64 inválido".into()))?;

    let recurso = state
        .recursos
        .crear(req.id, resource_type_id, &metadata_ciphertext, &metadata_nonce, auth.user_id, req.metadata_key_id)
        .await
        .map_err(DomainError::from)?;

    state.metadata_deks.guardar(recurso.id, auth.user_id, &sealed_dek).await.map_err(DomainError::from)?;

    Ok(Json(recurso_a_response(recurso, req.resource_type_slug)))
}

#[derive(serde::Deserialize)]
pub struct ActualizarMetadataOnlyRequest {
    pub metadata_ciphertext_b64: String,
    pub metadata_nonce_b64: String,
    pub sealed_dek_b64: String,
}

async fn actualizar_recurso_metadata_only(
    State(state): State<AppStateDesktop>,
    auth: AuthenticatedUserDesktop,
    Path(resource_id): Path<Uuid>,
    headers: HeaderMap,
    Json(req): Json<ActualizarMetadataOnlyRequest>,
) -> Result<Json<RecursoResponse>, ApiError> {
    if !state.permisos.tiene_permiso("resource", resource_id, auth.user_id, NivelPermiso::Update.as_db_str()).await.map_err(DomainError::from)? {
        return Err(DomainError::PermissionDenied.into());
    }

    let if_match = headers
        .get("if-match")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| DomainError::ValidacionInvalida("falta el header If-Match".into()))?;
    let expected_updated_at = OffsetDateTime::parse(if_match, &time::format_description::well_known::Rfc3339)
        .map_err(|_| DomainError::ValidacionInvalida("If-Match debe ser una fecha RFC3339 válida".into()))?;

    let metadata_ciphertext = b64::decode(&req.metadata_ciphertext_b64)
        .map_err(|_| DomainError::ValidacionInvalida("metadata_ciphertext_b64 inválido".into()))?;
    let metadata_nonce = b64::decode(&req.metadata_nonce_b64)
        .map_err(|_| DomainError::ValidacionInvalida("metadata_nonce_b64 inválido".into()))?;
    let sealed_dek = b64::decode(&req.sealed_dek_b64)
        .map_err(|_| DomainError::ValidacionInvalida("sealed_dek_b64 inválido".into()))?;

    let recurso = state
        .recursos
        .actualizar_metadata_solo(resource_id, expected_updated_at, &metadata_ciphertext, &metadata_nonce)
        .await
        .map_err(DomainError::from)?
        .ok_or(DomainError::Conflict)?;

    state.metadata_deks.guardar(recurso.id, auth.user_id, &sealed_dek).await.map_err(DomainError::from)?;

    let slug = state.tipos_recurso.mapa_id_a_slug().await.map_err(DomainError::from)?.get(&recurso.resource_type_id).cloned().unwrap_or_default();
    Ok(Json(recurso_a_response(recurso, slug)))
}

#[derive(serde::Serialize)]
pub struct MetadataDekResponse {
    pub sealed_dek_b64: String,
}

/// `GET /resources/{id}/metadata-dek` — mismo criterio anti-enumeración que
/// `obtener_secreto`: 404 uniforme si no hay fila, sin distinguir "no existe"
/// de "no te pertenece" (acá siempre es lo mismo, sólo hay un usuario local,
/// pero se mantiene el mismo shape de respuesta que el resto de la API).
async fn obtener_metadata_dek(
    State(state): State<AppStateDesktop>,
    auth: AuthenticatedUserDesktop,
    Path(resource_id): Path<Uuid>,
) -> Result<Json<MetadataDekResponse>, ApiError> {
    let sealed_dek = state.metadata_deks.buscar(resource_id, auth.user_id).await.map_err(DomainError::from)?.ok_or(DomainError::NotFound)?;
    Ok(Json(MetadataDekResponse { sealed_dek_b64: b64::encode(&sealed_dek) }))
}

/// El blob de la clave privada usa el correo como AAD, así que el cliente
/// tiene que mandarlo ya re-sellado con el correo nuevo (misma idea que
/// `POST /me/change-passphrase` en modo servidor) — el backend nunca ve la
/// passphrase ni las claves, sólo bytes opacos.
#[derive(serde::Deserialize)]
pub struct CambiarEmailRequest {
    pub new_email: String,
    pub encrypted_private_key_blob_b64: String,
    pub private_key_nonce_b64: String,
    pub kdf_salt_b64: String,
}

#[derive(serde::Serialize)]
pub struct CambiarEmailResponse {
    pub email: String,
}

/// Forma mínima de correo — `algo@dominio`, sin espacios ni caracteres de
/// control. No intenta validar el RFC completo (el registro tampoco lo hace,
/// sólo el `type=email` del navegador): acá el correo es sólo un
/// identificador local que el usuario quiere alinear con el de su cuenta del
/// servidor, y esa cuenta es la que decide si lo acepta.
fn email_con_forma_valida(email: &str) -> bool {
    if email.len() < 3 || email.len() > 254 || email.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    match email.split_once('@') {
        Some((local, dominio)) => !local.is_empty() && !dominio.is_empty() && !dominio.contains('@'),
        None => false,
    }
}

/// `PUT /me/email` — punto 6 de la lista de pendientes de escritorio: la
/// cuenta local nace desconectada y con el correo que el usuario haya
/// tipeado; para vincularla después a una cuenta del servidor central ese
/// correo tiene que coincidir con el de allá, así que hace falta poder
/// cambiarlo. Sólo existe en el router de escritorio (en modo servidor el
/// correo es la identidad de una cuenta multiusuario). Lo que está atado al
/// correo del lado del cliente (llavero, desbloqueo rápido, vinculación) lo
/// migra/invalida el frontend.
async fn cambiar_email_local(
    State(state): State<AppStateDesktop>,
    auth: AuthenticatedUserDesktop,
    Json(req): Json<CambiarEmailRequest>,
) -> Result<Json<CambiarEmailResponse>, ApiError> {
    let nuevo = req.new_email.trim();
    if !email_con_forma_valida(nuevo) {
        return Err(DomainError::ValidacionInvalida("el correo no tiene una forma válida (algo@dominio)".into()).into());
    }

    let blob = b64::decode(&req.encrypted_private_key_blob_b64)
        .map_err(|_| DomainError::ValidacionInvalida("encrypted_private_key_blob_b64 inválido".into()))?;
    let nonce =
        b64::decode(&req.private_key_nonce_b64).map_err(|_| DomainError::ValidacionInvalida("private_key_nonce_b64 inválido".into()))?;
    let salt = b64::decode(&req.kdf_salt_b64).map_err(|_| DomainError::ValidacionInvalida("kdf_salt_b64 inválido".into()))?;
    if blob.is_empty() || nonce.len() != 24 || salt.is_empty() {
        return Err(DomainError::ValidacionInvalida("el blob re-sellado de la clave privada es inválido".into()).into());
    }

    match state.usuarios.actualizar_email_y_blob(auth.user_id, nuevo, &blob, &nonce, &salt).await {
        Ok(true) => Ok(Json(CambiarEmailResponse { email: nuevo.to_string() })),
        Ok(false) => Err(DomainError::NotFound.into()),
        Err(RepoError::Conflict) => Err(DomainError::ValidacionInvalida("ese correo ya está en uso".into()).into()),
        Err(e) => Err(DomainError::from(e).into()),
    }
}

// ---------------------------------------------------------------------------
// Punto 8: recuperación local SIN SMTP con el recovery kit (F-44). Las rutas
// del kit no estaban montadas en escritorio: el kit que Ajustes → Seguridad
// generaba y descargaba nunca quedaba registrado (el PUT daba 404) y el login
// se tragaba el error, así que nunca se ofrecía. El reset por correo (link +
// segundo factor por correo) no puede funcionar sin SMTP; acá la prueba de
// que quien recupera tiene el kit es criptográfica, no un correo:
// desellar el material con la privada del kit da la clave Ed25519 de la
// cuenta, y con ella se firma un challenge que el backend verifica contra la
// pública ya guardada. Sin el kit no hay forma de producir esa firma.
// ---------------------------------------------------------------------------

use crate::auth::repository::AuthChallengeRepository;
use crate::recovery_kit::dto::{
    EstadoResponse as EstadoKitResponse, GenerarRequest as GenerarKitRequest, GenerarResponse as GenerarKitResponse,
};
use crate::recovery_kit::repository::RecoveryKitRepository;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

/// `GET /me/recovery-kit` — nunca expone el contenido del kit, sólo su estado.
async fn recovery_kit_estado(
    State(state): State<AppStateDesktop>,
    auth: AuthenticatedUserDesktop,
) -> Result<Json<EstadoKitResponse>, ApiError> {
    let kit = state.recovery_kits.buscar_por_usuario(auth.user_id).await.map_err(DomainError::from)?;
    Ok(Json(match kit {
        Some(k) => EstadoKitResponse { configured: true, created_at: Some(k.created_at), must_rotate: k.must_rotate },
        None => EstadoKitResponse { configured: false, created_at: None, must_rotate: false },
    }))
}

/// `PUT /me/recovery-kit` — sirve para la generación inicial y para
/// regenerar: el `upsert` pisa el kit anterior y limpia `must_rotate`.
async fn recovery_kit_generar(
    State(state): State<AppStateDesktop>,
    auth: AuthenticatedUserDesktop,
    Json(req): Json<GenerarKitRequest>,
) -> Result<Json<GenerarKitResponse>, ApiError> {
    let clave = b64::decode(&req.kit_public_key_x25519_b64)
        .map_err(|_| DomainError::ValidacionInvalida("kit_public_key_x25519_b64 no es base64 válido".into()))?;
    let material = b64::decode(&req.sealed_identity_material_b64)
        .map_err(|_| DomainError::ValidacionInvalida("sealed_identity_material_b64 no es base64 válido".into()))?;
    if clave.len() != 32 {
        return Err(DomainError::ValidacionInvalida("kit_public_key_x25519 debe ser de 32 bytes".into()).into());
    }
    if material.is_empty() {
        return Err(DomainError::ValidacionInvalida("sealed_identity_material no puede estar vacío".into()).into());
    }

    let kit = state.recovery_kits.upsert(auth.user_id, &clave, &material).await.map_err(DomainError::from)?;
    Ok(Json(GenerarKitResponse { created_at: kit.created_at }))
}

#[derive(serde::Deserialize)]
pub struct MaterialKitLocalRequest {
    pub email: String,
}

#[derive(serde::Serialize)]
pub struct MaterialKitLocalResponse {
    pub sealed_identity_material_b64: String,
}

/// `POST /auth/recovery-kit/local/material` — sin sesión, a propósito (quien
/// perdió la passphrase no tiene ninguna). Devuelve el material sellado, que
/// sólo se abre con la privada del kit: sin ella es un blob opaco. 404
/// uniforme si no hay cuenta o no hay kit.
async fn recovery_kit_local_material(
    State(state): State<AppStateDesktop>,
    Json(req): Json<MaterialKitLocalRequest>,
) -> Result<Json<MaterialKitLocalResponse>, ApiError> {
    let user = state.usuarios.buscar_por_email(req.email.trim()).await.map_err(DomainError::from)?.ok_or(DomainError::NotFound)?;
    let kit = state.recovery_kits.buscar_por_usuario(user.id).await.map_err(DomainError::from)?.ok_or(DomainError::NotFound)?;
    Ok(Json(MaterialKitLocalResponse { sealed_identity_material_b64: b64::encode(&kit.sealed_identity_material) }))
}

#[derive(serde::Deserialize)]
pub struct RecuperarLocalRequest {
    pub email: String,
    /// Nonce emitido por `POST /auth/challenge` — se consume acá.
    pub nonce_b64: String,
    /// Firma Ed25519 de ese nonce con la clave recuperada del kit.
    pub signature_b64: String,
    pub encrypted_private_key_blob_b64: String,
    pub private_key_nonce_b64: String,
    pub kdf_salt_b64: String,
}

/// `POST /auth/recovery-kit/local/complete` — el cliente ya desselló el
/// material con la privada del kit y lo re-selló con una passphrase nueva.
/// Cualquier fallo de identidad (cuenta, kit, challenge o firma) devuelve el
/// mismo 401 — no se distingue cuál fue.
async fn recovery_kit_local_completar(
    State(state): State<AppStateDesktop>,
    Json(req): Json<RecuperarLocalRequest>,
) -> Result<(), ApiError> {
    let user = state.usuarios.buscar_por_email(req.email.trim()).await.map_err(DomainError::from)?.ok_or(DomainError::InvalidCredentials)?;

    // Sin kit no hay recuperación posible por este camino.
    state.recovery_kits.buscar_por_usuario(user.id).await.map_err(DomainError::from)?.ok_or(DomainError::InvalidCredentials)?;

    let nonce = b64::decode(&req.nonce_b64).map_err(|_| DomainError::InvalidCredentials)?;
    let firma_bytes = b64::decode(&req.signature_b64).map_err(|_| DomainError::InvalidCredentials)?;

    // Un solo uso, con TTL — igual que el login (`AuthService::verify`).
    if !state.challenges.consumir_challenge(user.id, &nonce).await.map_err(DomainError::from)? {
        return Err(DomainError::InvalidCredentials.into());
    }

    let keys = state.usuarios.buscar_keys(user.id).await.map_err(DomainError::from)?.ok_or(DomainError::InvalidCredentials)?;
    let publica: [u8; 32] = keys.public_key_ed25519.try_into().map_err(|_| DomainError::InvalidCredentials)?;
    let firma: [u8; 64] = firma_bytes.try_into().map_err(|_| DomainError::InvalidCredentials)?;
    VerifyingKey::from_bytes(&publica)
        .map_err(|_| DomainError::InvalidCredentials)?
        .verify(&nonce, &Signature::from_bytes(&firma))
        .map_err(|_| DomainError::InvalidCredentials)?;

    let blob = b64::decode(&req.encrypted_private_key_blob_b64)
        .map_err(|_| DomainError::ValidacionInvalida("encrypted_private_key_blob_b64 inválido".into()))?;
    let nonce_blob =
        b64::decode(&req.private_key_nonce_b64).map_err(|_| DomainError::ValidacionInvalida("private_key_nonce_b64 inválido".into()))?;
    let salt = b64::decode(&req.kdf_salt_b64).map_err(|_| DomainError::ValidacionInvalida("kdf_salt_b64 inválido".into()))?;
    if blob.is_empty() || nonce_blob.len() != 24 || salt.is_empty() {
        return Err(DomainError::ValidacionInvalida("el blob re-sellado de la clave privada es inválido".into()).into());
    }

    if !state
        .usuarios
        .reemplazar_clave_por_recuperacion(user.id, &blob, &nonce_blob, &salt)
        .await
        .map_err(DomainError::from)?
    {
        return Err(DomainError::NotFound.into());
    }

    // El kit usado queda obsoleto: el próximo login obliga a generar otro.
    state.recovery_kits.marcar_para_rotar(user.id).await.map_err(DomainError::from)?;
    Ok(())
}

#[derive(serde::Deserialize)]
pub struct SyncQuery {
    pub since: Option<String>,
}

#[derive(serde::Serialize)]
pub struct SyncFolderItemResponse {
    pub id: String,
    pub folder_id: Option<String>,
    pub name_ciphertext: Option<String>,
    pub name_nonce: Option<String>,
}

#[derive(serde::Serialize)]
pub struct SyncResponse {
    pub resources: Vec<RecursoResponse>,
    pub deleted_resource_ids: Vec<String>,
    pub folders: Vec<SyncFolderItemResponse>,
    pub deleted_folder_ids: Vec<String>,
    pub tags: Vec<TagResponse>,
    pub deleted_tag_ids: Vec<String>,
    pub server_time: String,
}

async fn sync_get(
    State(state): State<AppStateDesktop>,
    usuario: AuthenticatedUserDesktop,
    Query(query): Query<SyncQuery>,
) -> Result<Json<SyncResponse>, ApiError> {
    let ahora = OffsetDateTime::now_utc();
    let ahora_str = crate::desktop::sqlite_util::fmt_dt(ahora);

    let mut recursos_activos = Vec::new();
    let mut deleted_resources = Vec::new();

    if let Some(ref s) = query.since {
        let filas = sqlx::query(
            "select id, resource_type_id, metadata_ciphertext, metadata_nonce, created_by, created_at, \
             updated_at, metadata_key_type, metadata_key_id from resources \
             where created_by = ?1 and deleted_at is null and (updated_at > ?2 or created_at > ?2) \
             order by updated_at asc",
        )
        .bind(usuario.user_id.to_string())
        .bind(s)
        .fetch_all(&state.pool)
        .await
        .map_err(db_err)?;

        for f in filas {
            let res = crate::desktop::repositories::resources::fila_a_resource(&f).map_err(DomainError::from)?;
            let slug: String = sqlx::query_scalar("select slug from resource_types where id = ?1")
                .bind(res.resource_type_id.to_string())
                .fetch_one(&state.pool)
                .await
                .unwrap_or_else(|_| "login-password".to_string());
            recursos_activos.push(recurso_a_response(res, slug));
        }

        let filas_del: Vec<String> = sqlx::query_scalar(
            "select id from resources where created_by = ?1 and deleted_at is not null and deleted_at > ?2",
        )
        .bind(usuario.user_id.to_string())
        .bind(s)
        .fetch_all(&state.pool)
        .await
        .map_err(db_err)?;

        deleted_resources = filas_del;
    } else {
        let visibles = state.recursos.listar_visibles_por(usuario.user_id).await.map_err(DomainError::from)?;
        for res in visibles {
            let slug: String = sqlx::query_scalar("select slug from resource_types where id = ?1")
                .bind(res.resource_type_id.to_string())
                .fetch_one(&state.pool)
                .await
                .unwrap_or_else(|_| "login-password".to_string());
            recursos_activos.push(recurso_a_response(res, slug));
        }
    }

    let mut carpetas_activas = Vec::new();
    let mut deleted_folders = Vec::new();

    let filas_c = sqlx::query(
        "select fi.child_folder_id as id, fi.folder_id, fi.name_ciphertext, fi.name_nonce \
         from folder_items fi join folders f on f.id = fi.child_folder_id \
         where fi.user_id = ?1 and f.deleted_at is null",
    )
    .bind(usuario.user_id.to_string())
    .fetch_all(&state.pool)
    .await
    .map_err(db_err)?;

    for f in filas_c {
        use sqlx::Row;
        let c_bytes: Option<Vec<u8>> = f.get("name_ciphertext");
        let n_bytes: Option<Vec<u8>> = f.get("name_nonce");
        carpetas_activas.push(SyncFolderItemResponse {
            id: f.get("id"),
            folder_id: f.get("folder_id"),
            name_ciphertext: c_bytes.as_deref().map(b64::encode),
            name_nonce: n_bytes.as_deref().map(b64::encode),
        });
    }

    if let Some(ref s) = query.since {
        let filas_del_f: Vec<String> = sqlx::query_scalar(
            "select id from folders where deleted_at is not null and deleted_at > ?1",
        )
        .bind(s)
        .fetch_all(&state.pool)
        .await
        .map_err(db_err)?;
        deleted_folders = filas_del_f;
    }

    let tags = servicio_tags(&state).listar_disponibles(usuario.user_id).await?;
    let tags_dto = tags.into_iter().map(tag_a_response).collect();

    let mut deleted_tags = Vec::new();
    if let Some(ref s) = query.since {
        let filas_del_t: Vec<String> = sqlx::query_scalar(
            "select id from tags where created_by = ?1 and deleted_at is not null and deleted_at > ?2",
        )
        .bind(usuario.user_id.to_string())
        .bind(s)
        .fetch_all(&state.pool)
        .await
        .map_err(db_err)?;
        deleted_tags = filas_del_t;
    }

    Ok(Json(SyncResponse {
        resources: recursos_activos,
        deleted_resource_ids: deleted_resources,
        folders: carpetas_activas,
        deleted_folder_ids: deleted_folders,
        tags: tags_dto,
        deleted_tag_ids: deleted_tags,
        server_time: ahora_str,
    }))
}

async fn sync_post(
    State(_state): State<AppStateDesktop>,
    _usuario: AuthenticatedUserDesktop,
) -> Result<Json<serde_json::Value>, ApiError> {
    Ok(Json(serde_json::json!({
        "status": "synchronized",
        "conflicts": 0,
        "message": "Sincronización procesada correctamente"
    })))
}

pub fn construir_router_desktop(estado: AppStateDesktop) -> Router {
    Router::new()
        .route("/auth/register", post(register))
        .route("/auth/server-key", get(server_key))
        .route("/auth/existe-usuario", get(existe_usuario))
        .route("/auth/challenge", post(challenge))
        .route("/auth/key-material", post(key_material))
        .route("/auth/verify", post(verify))
        .route("/auth/verify-device", post(verify_device))
        .route("/resources", get(listar_recursos).post(crear_recurso))
        .route("/resources/metadata-only", post(crear_recurso_metadata_only))
        .route("/resources/{id}", get(obtener_recurso).put(editar_recurso).delete(eliminar_recurso))
        .route("/resources/{id}/metadata-only", put(actualizar_recurso_metadata_only))
        .route("/resources/{id}/metadata-dek", get(obtener_metadata_dek))
        .route("/resources/{id}/type", put(cambiar_tipo_recurso))
        .route("/resources/{id}/secret", get(obtener_secreto))
        .route("/resources/{id}/recipients", get(recipients))
        .route("/resources/{id}/move", put(mover_recurso))
        .route("/resources/{resource_id}/tags/{tag_id}", post(aplicar_tag).delete(quitar_tag))
        .route("/metadata-keys", get(metadata_keys_vacio))
        .route("/folders", get(listar_carpetas).post(crear_carpeta))
        .route("/folders/{id}", axum::routing::delete(eliminar_carpeta))
        .route("/folders/{id}/move", put(mover_carpeta))
        .route("/tags", get(listar_tags).post(crear_tag))
        .route("/tags/{id}", axum::routing::delete(eliminar_tag))
        .route("/password-policy", get(password_policy_default))
        .route("/me", get(me_perfil))
        .route("/me/permissions", get(me_permisos))
        .route("/me/preferences", get(preferencias_default).put(preferencias_actualizar))
        .route("/me/email", put(cambiar_email_local))
        .route("/me/recovery-kit", get(recovery_kit_estado).put(recovery_kit_generar))
        .route("/auth/logout", post(logout_local))
        .route("/auth/recovery-kit/local/material", post(recovery_kit_local_material))
        .route("/auth/recovery-kit/local/complete", post(recovery_kit_local_completar))
        .route("/export-policy", get(export_policy_default))
        .route("/export-events", post(export_events_noop))
        .route("/me/groups", get(me_grupos))
        .route("/admin/password-policy", get(admin_password_policy_default))
        .route("/external-share-policy", get(external_share_policy_default))
        .route("/vault/persistence", get(obtener_persistencia).put(cambiar_persistencia))
        .route("/vault/backups", get(listar_respaldos).post(crear_respaldo))
        .route("/sync", get(sync_get).post(sync_post))
        // CORS sólo para los orígenes de `origen::origen_permitido`: la app
        // embebida, las extensiones y (en debug) el servidor de Vite. Antes era
        // `Any`, que dejaba a cualquier página web abierta en el navegador leer
        // las respuestas de este backend.
        .layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::predicate(|origen, _| origen.to_str().is_ok_and(origen::origen_permitido)))
                .allow_methods(Any)
                .allow_headers(Any),
        )
        // La guardia va DESPUÉS del CORS a propósito: el último `layer` es el
        // más externo, así que corre primero y corta antes de todo lo demás.
        .layer(middleware::from_fn(guardia_origen_y_host))
        .with_state(estado)
}
