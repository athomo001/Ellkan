// Autor: Athan Espinoza

use axum::Json;
use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Response};

use crate::auth::extractor::AuthenticatedUser;
use crate::error::ApiError;
use crate::state::AppState;

use super::service::DatosPersonalesService;

/// `GET /me/personal-data` — descarga JSON con los datos personales de la
/// propia cuenta (pendiente #58). Sin caché: es información personal.
pub async fn exportar(State(state): State<AppState>, user: AuthenticatedUser) -> Result<Response, ApiError> {
    let datos = DatosPersonalesService { repo: &state.datos_personales }.exportar(user.user_id).await?;
    Ok((
        [
            (header::CONTENT_DISPOSITION, "attachment; filename=\"ellkan-datos-personales.json\""),
            (header::CACHE_CONTROL, "no-store"),
        ],
        Json(datos),
    )
        .into_response())
}
