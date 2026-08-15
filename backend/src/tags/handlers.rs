// Autor: Athan Espinoza

use axum::extract::{Path, State};
use axum::Json;
use uuid::Uuid;

use crate::admin::repository::RoleRepository;
use crate::auth::extractor::AuthenticatedUser;
use crate::error::{ApiError, DomainError};
use crate::state::AppState;

use super::dto::{CrearTagRequest, TagResponse};
use super::models::Tag;
use super::service::TagService;

type Servicio<'a> =
    TagService<'a, super::repository::PgTagRepository, crate::resources::repository::PgPermissionRepository>;

fn servicio(state: &AppState) -> Servicio<'_> {
    TagService { tags: &state.tags, permisos: &state.permisos }
}

fn a_response(tag: Tag) -> TagResponse {
    TagResponse { id: tag.id, name: tag.name, is_shared: tag.is_shared, created_by: tag.created_by }
}

pub async fn listar(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
) -> Result<Json<Vec<TagResponse>>, ApiError> {
    let tags = servicio(&state).listar_disponibles(auth.user_id).await?;
    Ok(Json(tags.into_iter().map(a_response).collect()))
}

pub async fn crear(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Json(req): Json<CrearTagRequest>,
) -> Result<Json<TagResponse>, ApiError> {
    let es_admin = state.roles.usuario_tiene_permiso(auth.user_id, "*").await.map_err(DomainError::from)?;
    let tag = servicio(&state).crear(auth.user_id, es_admin, req.id, &req.name, req.is_shared).await?;
    Ok(Json(a_response(tag)))
}

pub async fn aplicar(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path((resource_id, tag_id)): Path<(Uuid, Uuid)>,
) -> Result<(), ApiError> {
    servicio(&state).aplicar(auth.user_id, resource_id, tag_id).await?;
    Ok(())
}

pub async fn quitar(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path((resource_id, tag_id)): Path<(Uuid, Uuid)>,
) -> Result<(), ApiError> {
    servicio(&state).quitar(auth.user_id, resource_id, tag_id).await?;
    Ok(())
}
