// Autor: Athan Espinoza

use axum::extract::{Path, State};
use axum::Json;
use uuid::Uuid;

use crate::auth::extractor::AdminUser;
use crate::error::ApiError;
use crate::state::AppState;

use super::dto::{
    ActualizarActivoRequest, DryRunResponse, PurgaResponse, PurgarRequest, UsuarioResponse,
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
