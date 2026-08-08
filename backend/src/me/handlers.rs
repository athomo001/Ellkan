// Autor: Athan Espinoza

use axum::extract::State;
use axum::Json;

use crate::auth::extractor::AuthenticatedUser;
use crate::error::ApiError;
use crate::state::AppState;

use super::dto::{ActualizarPreferenciasRequest, PreferenciasResponse};
use super::models::Preferencias;
use super::repository::PgPreferenciasRepository;
use super::service::PreferenciasService;
use crate::password_policy::repository::PgPasswordPolicyRepository;

type Servicio<'a> = PreferenciasService<'a, PgPreferenciasRepository, PgPasswordPolicyRepository>;

fn servicio(state: &AppState) -> Servicio<'_> {
    PreferenciasService { preferencias: &state.preferencias_usuario, password_policy: &state.password_policy }
}

fn a_response(p: Preferencias) -> PreferenciasResponse {
    PreferenciasResponse {
        locale: p.locale,
        theme: p.theme,
        clipboard_clear_minutes: p.clipboard_clear_minutes,
        auto_lock_minutes: p.auto_lock_minutes,
    }
}

pub async fn obtener(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<Json<PreferenciasResponse>, ApiError> {
    let p = servicio(&state).obtener(user.user_id).await?;
    Ok(Json(a_response(p)))
}

pub async fn actualizar(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(req): Json<ActualizarPreferenciasRequest>,
) -> Result<Json<PreferenciasResponse>, ApiError> {
    let nueva = Preferencias {
        locale: req.locale,
        theme: req.theme,
        clipboard_clear_minutes: req.clipboard_clear_minutes,
        auto_lock_minutes: req.auto_lock_minutes,
    };
    let p = servicio(&state).actualizar(user.user_id, nueva).await?;
    Ok(Json(a_response(p)))
}
