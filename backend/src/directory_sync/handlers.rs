// Autor: Athan Espinoza

use axum::extract::State;
use axum::Json;

use crate::auth::extractor::AdminUser;
use crate::error::ApiError;
use crate::scim::repository::PgScimUserRepository;
use crate::state::AppState;

use super::dto::{ActualizarConfigRequest, ConfigResponse};
use super::models::{DirectorySyncConfig, ResultadoSync};
use super::repository::PgDirectorySyncConfigRepository;
use super::service::DirectorySyncService;

type Servicio<'a> = DirectorySyncService<'a, PgDirectorySyncConfigRepository, PgScimUserRepository>;

fn servicio(state: &AppState) -> Servicio<'_> {
    DirectorySyncService {
        config: &state.directory_sync_config,
        usuarios: &state.scim_users,
        secrets_key: &state.secrets_key,
        eventos: state.eventos.clone(),
    }
}

fn a_response(c: DirectorySyncConfig) -> ConfigResponse {
    ConfigResponse {
        ldap_url: c.ldap_url,
        bind_dn: c.bind_dn,
        require_starttls: c.require_starttls,
        base_dn: c.base_dn,
        user_filter: c.user_filter,
        attribute_mapping: c.attribute_mapping,
        last_sync_at: c.last_sync_at,
    }
}

pub async fn config(State(state): State<AppState>, _admin: AdminUser) -> Result<Json<ConfigResponse>, ApiError> {
    let c = servicio(&state).config().await?;
    Ok(Json(a_response(c)))
}

pub async fn actualizar_config(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(req): Json<ActualizarConfigRequest>,
) -> Result<Json<ConfigResponse>, ApiError> {
    let c = servicio(&state)
        .actualizar_config(
            admin.user_id,
            req.ldap_url,
            req.bind_dn,
            req.bind_password,
            req.require_starttls,
            req.base_dn,
            req.user_filter,
            req.attribute_mapping,
        )
        .await?;
    Ok(Json(a_response(c)))
}

pub async fn dry_run(State(state): State<AppState>, admin: AdminUser) -> Result<Json<ResultadoSync>, ApiError> {
    let resultado = servicio(&state).dry_run(admin.user_id).await?;
    Ok(Json(resultado))
}

pub async fn aplicar(State(state): State<AppState>, admin: AdminUser) -> Result<Json<ResultadoSync>, ApiError> {
    let resultado = servicio(&state).aplicar(admin.user_id).await?;
    Ok(Json(resultado))
}
