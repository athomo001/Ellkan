// Autor: Athan Espinoza

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::audit::models::{AuditEventType, EventoAuditoria};
use crate::auth::extractor::AdminUser;
use crate::error::ApiError;
use crate::eventos::DomainEvent;
use crate::state::AppState;
use ellkan_crypto::aleatoriedad::bytes_aleatorios;

use super::dto::{
    CrearScimUserRequest, ListarScimQuery, PatchScimUserRequest, ScimErrorResponse, ScimListResponse,
    ScimTokenResponse, ScimUserResponse,
};
use super::extractor::ScimAuth;
use super::models::ResultadoCrearUsuario;
use super::repository::PgScimUserRepository;
use super::service::ScimService;

type Servicio<'a> = ScimService<'a, PgScimUserRepository>;

fn servicio(state: &AppState) -> Servicio<'_> {
    ScimService { usuarios: &state.scim_users, eventos: state.eventos.clone() }
}

fn scim_error(status: StatusCode, detail: impl Into<String>) -> Response {
    (status, Json(ScimErrorResponse::new(status.as_u16(), detail))).into_response()
}

/// `POST /admin/scim-tokens` — el token en claro se devuelve **una sola
/// vez** (mismo criterio que el secreto TOTP en el QR de F-14); sólo el
/// hash queda persistido.
pub async fn crear_token(
    State(state): State<AppState>,
    admin: AdminUser,
) -> Result<Json<ScimTokenResponse>, ApiError> {
    let token_bytes: [u8; 32] = bytes_aleatorios();
    let token = B64.encode(token_bytes);
    let hash = Sha256::digest(token.as_bytes());

    use super::repository::ScimTokenRepository;
    state.scim_tokens.crear(Uuid::now_v7(), &hash).await.map_err(crate::error::DomainError::from)?;

    let _ = state.eventos.send(DomainEvent::Auditoria(
        EventoAuditoria::nuevo(AuditEventType::ScimTokenCreated, Some(admin.user_id)),
    ));

    Ok(Json(ScimTokenResponse { token }))
}

pub async fn crear_usuario(
    State(state): State<AppState>,
    _auth: ScimAuth,
    Json(req): Json<CrearScimUserRequest>,
) -> Response {
    let email = req.email();
    let nombre = req.nombre();
    let resultado = servicio(&state).crear_usuario(&req.external_id, &email, &nombre).await;

    match resultado {
        Ok(ResultadoCrearUsuario::Creado(u)) => {
            (StatusCode::CREATED, Json(ScimUserResponse::from(u))).into_response()
        }
        Ok(ResultadoCrearUsuario::YaExistiaPorExternalId(u)) => scim_error(
            StatusCode::CONFLICT,
            format!("ya existe un usuario con externalId={} (id={})", req.external_id, u.id),
        ),
        Ok(ResultadoCrearUsuario::ConflictoDeEmail) => {
            scim_error(StatusCode::CONFLICT, "el email ya pertenece a una cuenta existente")
        }
        Err(e) => ApiError::from(e).into_response(),
    }
}

pub async fn listar_usuarios(
    State(state): State<AppState>,
    _auth: ScimAuth,
    Query(query): Query<ListarScimQuery>,
) -> Result<Json<ScimListResponse>, ApiError> {
    let (usuarios, total) = servicio(&state).listar(query.start_index, query.count).await?;
    Ok(Json(ScimListResponse {
        schemas: vec!["urn:ietf:params:scim:api:messages:2.0:ListResponse".to_string()],
        total_results: total,
        start_index: query.start_index,
        items_per_page: usuarios.len() as i64,
        resources: usuarios.into_iter().map(ScimUserResponse::from).collect(),
    }))
}

pub async fn obtener_usuario(
    State(state): State<AppState>,
    _auth: ScimAuth,
    Path(id): Path<Uuid>,
) -> Result<Json<ScimUserResponse>, ApiError> {
    let u = servicio(&state).obtener(id).await?;
    Ok(Json(u.into()))
}

/// `PATCH /scim/v2/Users/{id}` — sólo soporta `Replace` de `active`
/// (RFC 7644 §3.5.2), el caso real que F-18 pide (desactivar sin borrar).
pub async fn patch_usuario(
    State(state): State<AppState>,
    _auth: ScimAuth,
    Path(id): Path<Uuid>,
    Json(req): Json<PatchScimUserRequest>,
) -> Response {
    let activo = req.operations.iter().find_map(|op| {
        let toca_active = op.path.as_deref() == Some("active") || op.value.get("active").is_some();
        if !toca_active {
            return None;
        }
        op.value.as_bool().or_else(|| op.value.get("active").and_then(|v| v.as_bool()))
    });

    let Some(activo) = activo else {
        return scim_error(StatusCode::BAD_REQUEST, "sólo se soporta un Operations que toque 'active'");
    };

    match servicio(&state).actualizar_activo(id, activo).await {
        Ok(u) => Json(ScimUserResponse::from(u)).into_response(),
        Err(e) => ApiError::from(e).into_response(),
    }
}
