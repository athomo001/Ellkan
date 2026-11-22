// Autor: Athan Espinoza

use axum::Json;
use axum::extract::State;

use crate::auth::extractor::AdminUser;
use crate::error::ApiError;
use crate::state::AppState;

use super::models::{EstadoAviso, hay_version_nueva, version_actual};
use super::repository::PgUpdateCheckRepository;
use super::service::UpdateCheckService;

fn servicio(state: &AppState) -> UpdateCheckService<'_, PgUpdateCheckRepository> {
    UpdateCheckService { repo: &state.update_check, eventos: state.eventos.clone() }
}

#[derive(serde::Serialize)]
pub struct UpdateCheckResponse {
    pub enabled: bool,
    pub current_version: Option<&'static str>,
    pub latest_version: Option<String>,
    pub release_url: Option<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub checked_at: Option<time::OffsetDateTime>,
    pub update_available: bool,
}

#[derive(serde::Deserialize)]
pub struct UpdateCheckRequest {
    pub enabled: bool,
}

fn a_response(e: EstadoAviso) -> UpdateCheckResponse {
    let actual = version_actual();
    UpdateCheckResponse {
        enabled: e.enabled,
        current_version: actual,
        update_available: e.enabled && hay_version_nueva(actual, e.latest_version.as_deref()),
        latest_version: e.latest_version,
        release_url: e.release_url,
        checked_at: e.checked_at,
    }
}

/// `GET /admin/update-check`.
pub async fn obtener(State(state): State<AppState>, _admin: AdminUser) -> Result<Json<UpdateCheckResponse>, ApiError> {
    Ok(Json(a_response(servicio(&state).obtener().await?)))
}

/// `PUT /admin/update-check` — al activarlo consulta enseguida, en segundo
/// plano (la respuesta no espera a GitHub); después, una vez al día.
pub async fn fijar(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(req): Json<UpdateCheckRequest>,
) -> Result<Json<UpdateCheckResponse>, ApiError> {
    let estado = servicio(&state).fijar_habilitado(admin.user_id, req.enabled).await?;
    if req.enabled {
        let repo = state.update_check.clone();
        let eventos = state.eventos.clone();
        tokio::spawn(async move {
            let _ = UpdateCheckService { repo: &repo, eventos }.consultar_si_corresponde().await;
        });
    }
    Ok(Json(a_response(estado)))
}
