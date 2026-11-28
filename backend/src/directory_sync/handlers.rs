// Autor: Athan Espinoza

use axum::Json;
use axum::extract::State;

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

pub(crate) fn servicio(state: &AppState) -> Servicio<'_> {
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
        directory_unreachable_policy: c.directory_unreachable_policy,
        grace_seconds: c.grace_seconds,
        session_revalidate_seconds: c.session_revalidate_seconds,
        auto_sync_enabled: c.auto_sync_enabled,
        poll_interval_seconds: c.poll_interval_seconds,
        max_deactivations_per_run: c.max_deactivations_per_run,
        last_auto_sync_error: c.last_auto_sync_error,
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
    let servicio = servicio(&state);
    if req.directory_unreachable_policy.is_some() || req.grace_seconds.is_some() || req.session_revalidate_seconds.is_some() {
        servicio
            .actualizar_verificacion(req.directory_unreachable_policy, req.grace_seconds, req.session_revalidate_seconds)
            .await?;
    }
    if req.auto_sync_enabled.is_some() || req.poll_interval_seconds.is_some() || req.max_deactivations_per_run.is_some() {
        servicio
            .actualizar_sync_automatico(
                req.auto_sync_enabled,
                req.poll_interval_seconds,
                req.max_deactivations_per_run.map(|t| if t == 0 { None } else { Some(t) }),
            )
            .await?;
    }
    let c = servicio
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

pub async fn aplicar(
    State(state): State<AppState>,
    admin: AdminUser,
    axum::extract::Query(q): axum::extract::Query<super::dto::AplicarQuery>,
) -> Result<Json<ResultadoSync>, ApiError> {
    let resultado = servicio(&state).aplicar(Some(admin.user_id), q.confirm_mass_deactivation).await?;
    Ok(Json(resultado))
}
