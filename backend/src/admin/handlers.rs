// Autor: Athan Espinoza

use axum::extract::{Path, State};
use axum::Json;
use uuid::Uuid;

use crate::auth::extractor::AdminUser;
use crate::error::ApiError;
use crate::state::AppState;

use super::dto::{ActualizarPermisosRequest, CrearRolRequest, RolResponse};
use super::models::Role;
use super::service::RoleService;

type Servicio<'a> = RoleService<'a, super::repository::PgRoleRepository>;

fn servicio(state: &AppState) -> Servicio<'_> {
    RoleService { roles: &state.roles }
}

fn a_response(rol: Role) -> RolResponse {
    RolResponse { id: rol.id, name: rol.name, permissions: rol.permissions, created_at: rol.created_at }
}

pub async fn listar(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<Vec<RolResponse>>, ApiError> {
    let roles = servicio(&state).listar().await?;
    Ok(Json(roles.into_iter().map(a_response).collect()))
}

pub async fn crear(
    State(state): State<AppState>,
    _admin: AdminUser,
    Json(req): Json<CrearRolRequest>,
) -> Result<Json<RolResponse>, ApiError> {
    let rol = servicio(&state).crear(&req.name, req.permissions).await?;
    Ok(Json(a_response(rol)))
}

pub async fn actualizar_permisos(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(role_id): Path<Uuid>,
    Json(req): Json<ActualizarPermisosRequest>,
) -> Result<Json<RolResponse>, ApiError> {
    let rol = servicio(&state).actualizar_permisos(role_id, req.permissions).await?;
    Ok(Json(a_response(rol)))
}
