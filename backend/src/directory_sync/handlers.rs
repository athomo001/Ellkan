// Autor: Athan Espinoza

use axum::extract::State;
use axum::Json;

use crate::auth::extractor::AdminUser;
use crate::error::ApiError;
use crate::groups::repository::{PgGroupMemberRepository, PgGroupRepository};
use crate::resources::repository::PgPermissionRepository;
use crate::scim::repository::PgScimUserRepository;
use crate::state::AppState;

use super::dto::{ActualizarConfigRequest, ConfigResponse};
use super::models::{DirectorySyncConfig, ResultadoSync};
use super::repository::PgDirectorySyncConfigRepository;
use super::service::DirectorySyncService;

type Servicio<'a> = DirectorySyncService<
    'a,
    PgDirectorySyncConfigRepository,
    PgScimUserRepository,
    PgGroupRepository,
    PgGroupMemberRepository,
    PgPermissionRepository,
>;

fn servicio(state: &AppState) -> Servicio<'_> {
    DirectorySyncService {
        config: &state.directory_sync_config,
        usuarios: &state.scim_users,
        grupos: &state.grupos,
        miembros: &state.miembros_de_grupo,
        permisos: &state.permisos,
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
        user_object_class: c.user_object_class,
        sync_groups: c.sync_groups,
        group_membership_attribute: c.group_membership_attribute,
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
            req.user_object_class,
            req.sync_groups,
            req.group_membership_attribute,
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
