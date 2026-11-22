// Autor: Athan Espinoza

use axum::Json;
use axum::extract::State;

use crate::auth::extractor::AdminUser;
use crate::error::ApiError;
use crate::state::AppState;

use super::models::TextosLegales;
use super::repository::PgLegalLinksRepository;
use super::service::LegalLinksService;

fn servicio(state: &AppState) -> LegalLinksService<'_, PgLegalLinksRepository> {
    LegalLinksService { repo: &state.legal_links, eventos: state.eventos.clone() }
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Default)]
pub struct LegalLinksDto {
    #[serde(default)]
    pub privacy_url: Option<String>,
    #[serde(default)]
    pub terms_url: Option<String>,
}

impl From<TextosLegales> for LegalLinksDto {
    fn from(t: TextosLegales) -> Self {
        LegalLinksDto { privacy_url: t.privacy_url, terms_url: t.terms_url }
    }
}

/// `GET /admin/legal-links`.
pub async fn obtener(State(state): State<AppState>, _admin: AdminUser) -> Result<Json<LegalLinksDto>, ApiError> {
    Ok(Json(servicio(&state).obtener().await?.into()))
}

/// `PUT /admin/legal-links` — un link vacío lo quita.
pub async fn actualizar(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(req): Json<LegalLinksDto>,
) -> Result<Json<LegalLinksDto>, ApiError> {
    let textos = servicio(&state)
        .actualizar(admin.user_id, req.privacy_url.as_deref(), req.terms_url.as_deref())
        .await?;
    Ok(Json(textos.into()))
}
