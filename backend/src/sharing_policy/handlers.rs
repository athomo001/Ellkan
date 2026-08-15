// Autor: Athan Espinoza

use axum::extract::State;
use axum::Json;

use crate::auth::extractor::AdminUser;
use crate::error::ApiError;
use crate::state::AppState;

use super::dto::{ActualizarSharingPolicyRequest, SharingPolicyResponse};
use super::models::SharingPolicy;
use super::repository::PgSharingPolicyRepository;
use super::service::SharingPolicyService;

type Servicio<'a> = SharingPolicyService<'a, PgSharingPolicyRepository>;

fn servicio(state: &AppState) -> Servicio<'_> {
    SharingPolicyService { policy: &state.sharing_policy, eventos: state.eventos.clone() }
}

fn a_response(p: SharingPolicy) -> SharingPolicyResponse {
    SharingPolicyResponse { restrict_visibility_by_group: p.restrict_visibility_by_group }
}

pub async fn politica(State(state): State<AppState>, _admin: AdminUser) -> Result<Json<SharingPolicyResponse>, ApiError> {
    let p = servicio(&state).obtener().await?;
    Ok(Json(a_response(p)))
}

pub async fn actualizar_politica(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(req): Json<ActualizarSharingPolicyRequest>,
) -> Result<Json<SharingPolicyResponse>, ApiError> {
    let nueva = SharingPolicy { restrict_visibility_by_group: req.restrict_visibility_by_group };
    let p = servicio(&state).actualizar(admin.user_id, nueva).await?;
    Ok(Json(a_response(p)))
}
