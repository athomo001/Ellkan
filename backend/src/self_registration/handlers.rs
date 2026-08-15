// Autor: Athan Espinoza

use axum::extract::State;
use axum::Json;

use crate::auth::extractor::AdminUser;
use crate::error::ApiError;
use crate::state::AppState;

use super::dto::{ActualizarSelfRegistrationPolicyRequest, SelfRegistrationPolicyResponse};
use super::models::SelfRegistrationPolicy;
use super::repository::PgSelfRegistrationPolicyRepository;
use super::service::SelfRegistrationPolicyService;

type Servicio<'a> = SelfRegistrationPolicyService<'a, PgSelfRegistrationPolicyRepository>;

fn servicio(state: &AppState) -> Servicio<'_> {
    SelfRegistrationPolicyService { policy: &state.self_registration_policy, eventos: state.eventos.clone() }
}

fn a_response(p: SelfRegistrationPolicy) -> SelfRegistrationPolicyResponse {
    SelfRegistrationPolicyResponse { enabled: p.enabled, allowed_domains: p.allowed_domains }
}

/// No hay GET público — un cliente anónimo no necesita saber la política
/// antes de intentar registrarse, mismo criterio que
/// `account-recovery-policy`/`sso-config`.
pub async fn politica(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<SelfRegistrationPolicyResponse>, ApiError> {
    let p = servicio(&state).obtener().await?;
    Ok(Json(a_response(p)))
}

pub async fn actualizar_politica(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(req): Json<ActualizarSelfRegistrationPolicyRequest>,
) -> Result<Json<SelfRegistrationPolicyResponse>, ApiError> {
    let nueva = SelfRegistrationPolicy { enabled: req.enabled, allowed_domains: req.allowed_domains };
    let p = servicio(&state).actualizar(admin.user_id, nueva).await?;
    Ok(Json(a_response(p)))
}
