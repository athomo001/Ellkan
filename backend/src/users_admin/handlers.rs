// Autor: Athan Espinoza

use axum::extract::{Path, Query, State};
use axum::http::header;
use axum::response::IntoResponse;
use axum::Json;
use uuid::Uuid;

use crate::auth::extractor::AdminUser;
use crate::error::{ApiError, DomainError};
use crate::me::service::AvatarService;
use crate::state::AppState;

use super::dto::{
    ActualizarActivoRequest, DryRunResponse, ListarUsuariosQuery, PurgaResponse, PurgarRequest, UsuarioResponse,
    UsuariosPageResponse,
};
use super::repository::PgUserPurgeRepository;
use super::service::UsersAdminService;

type Servicio<'a> = UsersAdminService<'a, PgUserPurgeRepository>;

fn servicio(state: &AppState) -> Servicio<'_> {
    UsersAdminService { repo: &state.users_purge, eventos: state.eventos.clone() }
}

pub async fn obtener(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(id): Path<Uuid>,
) -> Result<Json<UsuarioResponse>, ApiError> {
    let u = servicio(&state).obtener(id).await?;
    Ok(Json(u.into()))
}

pub async fn actualizar_activo(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<Uuid>,
    Json(req): Json<ActualizarActivoRequest>,
) -> Result<Json<UsuarioResponse>, ApiError> {
    let servicio = servicio(&state);
    if req.active {
        servicio.activar(admin.user_id, id).await?;
    } else {
        servicio.desactivar(admin.user_id, id).await?;
    }
    let u = servicio.obtener(id).await?;
    Ok(Json(u.into()))
}

pub async fn purge_dry_run(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(id): Path<Uuid>,
) -> Result<Json<DryRunResponse>, ApiError> {
    let bloqueos = servicio(&state).dry_run_purga(id).await?;
    Ok(Json(bloqueos.into()))
}

pub async fn purgar(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<Uuid>,
    Json(req): Json<PurgarRequest>,
) -> Result<Json<PurgaResponse>, ApiError> {
    let resultado = servicio(&state).purgar(admin.user_id, id, req.transfer.into()).await?;
    Ok(Json(PurgaResponse { resources_huerfanos_eliminados: resultado.resources_huerfanos_eliminados }))
}

/// `GET /admin/users` (F-29) — listado completo paginado, a diferencia de
/// `/admin/users/{id}` (necesita el id de antemano) o la búsqueda por email
/// de F-01 (`/users/{email}/public-key`).
pub async fn listar(
    State(state): State<AppState>,
    _admin: AdminUser,
    Query(q): Query<ListarUsuariosQuery>,
) -> Result<Json<UsuariosPageResponse>, ApiError> {
    let (usuarios, next_cursor) = servicio(&state).listar(q.active, q.cursor, q.limit).await?;
    Ok(Json(UsuariosPageResponse { items: usuarios.into_iter().map(UsuarioResponse::from).collect(), next_cursor }))
}

/// `GET /admin/users/{id}/avatar` — post-cierre bloque C, mismo servicio
/// que `GET /me/avatar` (`me::service::AvatarService`, ya genérico en
/// `user_id`), sólo con `AdminUser` en vez del propio usuario.
pub async fn avatar(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let avatar = AvatarService { avatar: &state.preferencias_usuario }.obtener(id).await?;
    match avatar {
        Some(a) => Ok(([(header::CONTENT_TYPE, a.content_type)], a.bytes).into_response()),
        None => Err(ApiError::from(DomainError::NotFound)),
    }
}
