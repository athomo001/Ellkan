// Autor: Athan Espinoza

use axum::extract::State;
use axum::Json;

use crate::auth::extractor::AdminUser;
use crate::error::ApiError;
use crate::state::AppState;

use super::dto::{ActualizarSmtpConfigRequest, ProbarSmtpRequest, ProbarSmtpResponse, SmtpConfigResponse};
use super::models::SmtpConfig;
use super::repository::PgSmtpConfigRepository;
use super::service::SmtpConfigService;
use crate::notificaciones::PgOutboundEmailRepository;

type Servicio<'a> = SmtpConfigService<'a, PgSmtpConfigRepository, PgOutboundEmailRepository>;

fn servicio(state: &AppState) -> Servicio<'_> {
    SmtpConfigService {
        repo: &state.smtp_config,
        emails: &state.emails,
        secrets_key: &state.secrets_key,
        eventos: state.eventos.clone(),
    }
}

fn a_response(c: SmtpConfig) -> SmtpConfigResponse {
    SmtpConfigResponse {
        configurado: c.esta_configurado(),
        host: c.host,
        port: c.port,
        from_address: c.from_address,
        tls: c.tls,
        username: c.username,
    }
}

pub async fn obtener(State(state): State<AppState>, _admin: AdminUser) -> Result<Json<SmtpConfigResponse>, ApiError> {
    let c = servicio(&state).obtener().await?;
    Ok(Json(a_response(c)))
}

pub async fn actualizar(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(req): Json<ActualizarSmtpConfigRequest>,
) -> Result<Json<SmtpConfigResponse>, ApiError> {
    let c = servicio(&state)
        .actualizar(admin.user_id, req.host, req.port, req.from_address, req.tls, req.username, req.password)
        .await?;
    Ok(Json(a_response(c)))
}

pub async fn probar(
    State(state): State<AppState>,
    _admin: AdminUser,
    Json(req): Json<ProbarSmtpRequest>,
) -> Result<Json<ProbarSmtpResponse>, ApiError> {
    let status = servicio(&state).probar_envio(&req.to).await?;
    Ok(Json(ProbarSmtpResponse { status }))
}
