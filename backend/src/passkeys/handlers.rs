// Autor: Athan Espinoza

use axum::extract::{Path, State};
use axum::Json;
use uuid::Uuid;
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};

use crate::auth::extractor::AuthenticatedUser;
use crate::b64;
use crate::error::{ApiError, DomainError};
use crate::state::AppState;

use super::dto::{
    FinalizarAutenticacionRequest, FinalizarRegistroRequest, IniciarAutenticacionRequest,
    PasskeyResponse, SesionWebauthnResponse,
};
use super::models::PasskeyRow;
use super::service::PasskeyService;

type Servicio<'a> = PasskeyService<
    'a,
    super::repository::PgPasskeyRepository,
    super::repository::PgCeremonyStateRepository,
    crate::auth::repository::PgUserRepository,
    crate::auth::repository::PgSessionRepository,
>;

fn servicio(state: &AppState) -> Servicio<'_> {
    PasskeyService {
        passkeys: &state.passkeys,
        ceremonias: &state.ceremonias_webauthn,
        usuarios: &state.usuarios,
        sesiones: &state.sesiones,
        webauthn: state.webauthn.clone(),
        eventos: state.eventos.clone(),
    }
}

fn a_response(p: PasskeyRow) -> PasskeyResponse {
    PasskeyResponse {
        id: p.id,
        label: p.label,
        created_at: p.created_at,
        last_used_at: p.last_used_at,
        tiene_prf: p.prf_wrapped_private_key.is_some(),
    }
}

pub async fn register_options(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
) -> Result<Json<CreationChallengeResponse>, ApiError> {
    let ccr = servicio(&state).iniciar_registro(auth.user_id).await?;
    Ok(Json(ccr))
}

pub async fn register_verify(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Json(req): Json<FinalizarRegistroRequest>,
) -> Result<(), ApiError> {
    let prf_wrapped = req
        .prf_wrapped_private_key_b64
        .as_deref()
        .map(b64::decode)
        .transpose()
        .map_err(|_| DomainError::ValidacionInvalida("prf_wrapped_private_key_b64 inválido".into()))?;

    servicio(&state)
        .finalizar_registro(auth.user_id, req.credential, prf_wrapped, req.label)
        .await?;
    Ok(())
}

pub async fn login_options(
    State(state): State<AppState>,
    Json(req): Json<IniciarAutenticacionRequest>,
) -> Result<Json<RequestChallengeResponse>, ApiError> {
    let rcr = servicio(&state).iniciar_autenticacion(&req.email).await?;
    Ok(Json(rcr))
}

pub async fn login_verify(
    State(state): State<AppState>,
    Json(req): Json<FinalizarAutenticacionRequest>,
) -> Result<Json<SesionWebauthnResponse>, ApiError> {
    let (sesion, prf_wrapped) = servicio(&state).finalizar_autenticacion(&req.email, req.credential).await?;
    Ok(Json(SesionWebauthnResponse {
        session_id: sesion.id,
        user_id: sesion.user_id,
        prf_wrapped_private_key_b64: prf_wrapped.as_deref().map(b64::encode),
    }))
}

/// `GET /me/passkeys` (F-03).
pub async fn listar(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
) -> Result<Json<Vec<PasskeyResponse>>, ApiError> {
    let passkeys = servicio(&state).listar(auth.user_id).await?;
    Ok(Json(passkeys.into_iter().map(a_response).collect()))
}

/// `DELETE /me/passkeys/{id}` (F-03).
pub async fn revocar(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path(passkey_id): Path<Uuid>,
) -> Result<(), ApiError> {
    servicio(&state).revocar(auth.user_id, passkey_id).await?;
    Ok(())
}
