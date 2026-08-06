// Autor: Athan Espinoza

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;

use crate::auth::extractor::AdminUser;
use crate::auth::models::ResultadoVerify;
use crate::error::ApiError;
use crate::state::AppState;

use super::dto::{ActualizarSsoConfigRequest, CallbackQuery, LoginCompletoResponse, SsoConfigResponse};
use super::models::SsoConfig;
use super::repository::{PgLoginStateRepository, PgSsoConfigRepository, PgSsoIdentityRepository};
use super::service::SsoService;
use crate::auth::repository::PgUserRepository;

type Servicio<'a> = SsoService<
    'a,
    PgSsoConfigRepository,
    PgSsoIdentityRepository,
    PgLoginStateRepository,
    PgUserRepository,
>;

/// Mismo criterio que `ELLKAN_RP_ORIGIN` (F-03): default de desarrollo,
/// producción debe fijar la variable a su origen real.
fn redirect_url(_state: &AppState) -> String {
    std::env::var("ELLKAN_SSO_REDIRECT_URL")
        .unwrap_or_else(|_| "http://localhost:8080/auth/sso/oidc/callback".to_string())
}

fn servicio(state: &AppState) -> Servicio<'_> {
    SsoService {
        config: &state.sso_config,
        identities: &state.sso_identities,
        login_state: &state.sso_login_state,
        usuarios: &state.usuarios,
        redirect_url: redirect_url(state),
        eventos: state.eventos.clone(),
    }
}

#[allow(clippy::type_complexity)]
fn auth_service(
    state: &AppState,
) -> crate::auth::service::AuthService<
    '_,
    PgUserRepository,
    crate::auth::repository::PgAuthChallengeRepository,
    crate::auth::repository::PgSessionRepository,
    crate::auth::repository::PgKnownDeviceRepository,
    crate::auth::repository::PgDeviceChallengeRepository,
    crate::mfa::repository::PgMfaPolicyRepository,
    crate::mfa::repository::PgTotpCredentialRepository,
    crate::mfa::repository::PgMfaChallengeRepository,
> {
    crate::auth::service::AuthService {
        usuarios: &state.usuarios,
        challenges: &state.challenges,
        sesiones: &state.sesiones,
        dispositivos: &state.dispositivos,
        desafios_dispositivo: &state.desafios_dispositivo,
        mfa_policy: &state.mfa_policy,
        mfa_totp: &state.mfa_totp,
        mfa_challenges: &state.mfa_challenges,
        eventos: state.eventos.clone(),
    }
}

pub async fn config(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<SsoConfigResponse>, ApiError> {
    let c = servicio(&state).config().await?;
    Ok(Json(SsoConfigResponse {
        issuer_url: c.issuer_url,
        client_id: c.client_id,
        jit_provisioning_enabled: c.jit_provisioning_enabled,
    }))
}

pub async fn actualizar_config(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(req): Json<ActualizarSsoConfigRequest>,
) -> Result<Json<SsoConfigResponse>, ApiError> {
    let nueva = SsoConfig {
        issuer_url: req.issuer_url,
        client_id: req.client_id,
        jit_provisioning_enabled: req.jit_provisioning_enabled,
    };
    let c = servicio(&state).actualizar_config(admin.user_id, nueva).await?;
    Ok(Json(SsoConfigResponse {
        issuer_url: c.issuer_url,
        client_id: c.client_id,
        jit_provisioning_enabled: c.jit_provisioning_enabled,
    }))
}

/// `GET /auth/sso/{provider}/redirect` — sólo `oidc` implementado (SAML
/// pospuesto, F-17). Redirect real (302) para un browser; nuestros tests de
/// integración lo siguen manualmente para poder inspeccionar la URL.
pub async fn redirect(
    State(state): State<AppState>,
    Path(provider): Path<String>,
) -> Result<Response, ApiError> {
    if provider != "oidc" {
        return Ok((StatusCode::NOT_FOUND, "proveedor no soportado").into_response());
    }
    let url = servicio(&state).iniciar_login().await?;
    Ok(Redirect::to(&url).into_response())
}

pub async fn callback(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    Query(query): Query<CallbackQuery>,
) -> Result<Json<LoginCompletoResponse>, ApiError> {
    if provider != "oidc" {
        return Err(crate::error::DomainError::NotFound.into());
    }
    let user = servicio(&state).resolver_callback(query.code, &query.state).await?;

    let resultado = auth_service(&state).resolver_tras_f02(user).await?;

    Ok(Json(match resultado {
        ResultadoVerify::SesionCompleta(s) => {
            LoginCompletoResponse { estado: "completo".into(), session_id: Some(s.id) }
        }
        ResultadoVerify::PendienteMfa { session_id } => {
            LoginCompletoResponse { estado: "pendiente_mfa".into(), session_id: Some(session_id) }
        }
        ResultadoVerify::RequiereConfigurarMfa { session_id } => {
            LoginCompletoResponse { estado: "requiere_configurar_mfa".into(), session_id: Some(session_id) }
        }
        ResultadoVerify::PendienteDispositivo { .. } => unreachable!("SSO nunca pasa por F-02"),
    }))
}

