// Autor: Athan Espinoza

use axum::extract::State;
use axum::Json;

use crate::auth::extractor::AdminUser;
use crate::state::AppState;

use super::models::GrupoChecks;
use super::service::SystemStatusService;

type Servicio<'a> = SystemStatusService<
    'a,
    super::repository::PgSystemStatusRepository,
    crate::notificaciones::PgOutboundEmailRepository,
    crate::smtp_config::repository::PgSmtpConfigRepository,
    crate::sso::repository::PgSsoConfigRepository,
    crate::directory_sync::repository::PgDirectorySyncConfigRepository,
    crate::metadata::repository::PgMetadataKeyRepository,
>;

fn servicio(state: &AppState) -> Servicio<'_> {
    SystemStatusService {
        system_status: &state.system_status,
        emails: &state.emails,
        smtp_config: &state.smtp_config,
        sso_config: &state.sso_config,
        directory_sync_config: &state.directory_sync_config,
        claves_metadata: &state.claves_metadata,
    }
}

/// `GET /admin/system-status` — siempre `200` con sesión admin válida; cada
/// check individual refleja su propio fallo en `nivel`, nunca un `500` por
/// el error de un check aislado (ver `service.rs`).
pub async fn obtener(State(state): State<AppState>, _admin: AdminUser) -> Json<Vec<GrupoChecks>> {
    Json(servicio(&state).obtener_todo().await)
}
