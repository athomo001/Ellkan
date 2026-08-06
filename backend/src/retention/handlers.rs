// Autor: Athan Espinoza

use axum::extract::State;
use axum::Json;

use crate::auth::extractor::AdminUser;
use crate::error::ApiError;
use crate::state::AppState;

use super::dto::{ActualizarRetentionPolicyRequest, RetentionPolicyResponse};
use super::repository::{PgPurgeRepository, PgRetentionPolicyRepository};
use super::service::RetentionService;

type Servicio<'a> = RetentionService<'a, PgRetentionPolicyRepository, PgPurgeRepository>;

fn servicio(state: &AppState) -> Servicio<'_> {
    RetentionService { policy: &state.retention_policy, purga: &state.purge, eventos: state.eventos.clone() }
}

pub async fn politica(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<RetentionPolicyResponse>, ApiError> {
    let p = servicio(&state).politica().await?;
    Ok(Json(RetentionPolicyResponse {
        data_retention_days: p.data_retention_days,
        audit_log_retention_days: p.audit_log_retention_days,
    }))
}

pub async fn actualizar_politica(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(req): Json<ActualizarRetentionPolicyRequest>,
) -> Result<Json<RetentionPolicyResponse>, ApiError> {
    let p = servicio(&state)
        .actualizar_politica(admin.user_id, req.data_retention_days, req.audit_log_retention_days)
        .await?;
    Ok(Json(RetentionPolicyResponse {
        data_retention_days: p.data_retention_days,
        audit_log_retention_days: p.audit_log_retention_days,
    }))
}
