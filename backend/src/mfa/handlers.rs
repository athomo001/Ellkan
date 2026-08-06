// Autor: Athan Espinoza

use axum::extract::State;
use axum::Json;
use base32::Alphabet;

use crate::auth::extractor::{AdminUser, SesionValida};
use crate::error::{ApiError, DomainError};
use crate::state::AppState;

use super::dto::{
    ActualizarMfaPolicyRequest, ConfirmarTotpRequest, MfaPolicyResponse, SetupTotpResponse,
    VerificarMfaRequest,
};
use super::models::MfaPolicy;
use super::repository::{PgMfaChallengeRepository, PgMfaPolicyRepository, PgTotpCredentialRepository};
use super::service::MfaService;
use crate::auth::repository::PgSessionRepository;

type Servicio<'a> =
    MfaService<'a, PgMfaPolicyRepository, PgTotpCredentialRepository, PgMfaChallengeRepository, PgSessionRepository>;

fn servicio(state: &AppState) -> Servicio<'_> {
    MfaService {
        policy: &state.mfa_policy,
        totp: &state.mfa_totp,
        challenges: &state.mfa_challenges,
        sesiones: &state.sesiones,
        secrets_key: &state.secrets_key,
        eventos: state.eventos.clone(),
    }
}

fn a_response(p: MfaPolicy) -> MfaPolicyResponse {
    MfaPolicyResponse {
        require_mfa: p.require_mfa,
        allowed_methods: p.allowed_methods,
        grace_period_days: p.grace_period_days,
        require_mfa_since: p.require_mfa_since,
    }
}

pub async fn politica(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<MfaPolicyResponse>, ApiError> {
    let p = servicio(&state).obtener_politica().await?;
    Ok(Json(a_response(p)))
}

pub async fn actualizar_politica(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(req): Json<ActualizarMfaPolicyRequest>,
) -> Result<Json<MfaPolicyResponse>, ApiError> {
    let p = servicio(&state)
        .actualizar_politica(admin.user_id, req.require_mfa, req.allowed_methods, req.grace_period_days)
        .await?;
    Ok(Json(a_response(p)))
}

fn codificar_secreto_base32(secreto: &[u8]) -> String {
    base32::encode(Alphabet::Rfc4648 { padding: false }, secreto)
}

/// `otpauth://` estándar (RFC de facto que siguen todas las apps
/// autenticadoras) — `issuer`/`account` fijos acá porque el endpoint no
/// recibe el email todavía; suficiente para escanear el QR.
fn otpauth_uri(secreto_base32: &str) -> String {
    format!("otpauth://totp/Ellkan?secret={secreto_base32}&issuer=Ellkan&algorithm=SHA1&digits=6&period=30")
}

pub async fn setup_totp(
    State(state): State<AppState>,
    sesion: SesionValida,
) -> Result<Json<SetupTotpResponse>, ApiError> {
    let secreto = servicio(&state).iniciar_setup_totp(sesion.user_id).await?;
    let secret_base32 = codificar_secreto_base32(&secreto);
    let otpauth_uri = otpauth_uri(&secret_base32);
    Ok(Json(SetupTotpResponse { secret_base32, otpauth_uri }))
}

fn parsear_codigo(code: &str) -> Result<u32, ApiError> {
    code.trim()
        .parse::<u32>()
        .map_err(|_| DomainError::ValidacionInvalida("code debe ser un número de 6 dígitos".into()).into())
}

pub async fn confirm_totp(
    State(state): State<AppState>,
    sesion: SesionValida,
    Json(req): Json<ConfirmarTotpRequest>,
) -> Result<(), ApiError> {
    let codigo = parsear_codigo(&req.code)?;
    servicio(&state).confirmar_setup_totp(sesion.user_id, codigo, sesion.session_id).await?;
    Ok(())
}

pub async fn verify(
    State(state): State<AppState>,
    sesion: SesionValida,
    Json(req): Json<VerificarMfaRequest>,
) -> Result<(), ApiError> {
    let codigo = parsear_codigo(&req.code)?;
    servicio(&state).verificar_login(sesion.user_id, sesion.session_id, codigo).await?;
    Ok(())
}
