// Autor: Athan Espinoza

use axum::extract::{Path, State};
use axum::Json;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use crate::auth::extractor::AuthenticatedUser;
use crate::auth::repository::PgUserRepository;
use crate::error::{ApiError, DomainError};
use crate::me::models::NuevaClavePrivada;
use crate::me::repository::PgPreferenciasRepository;
use crate::mfa::repository::PgTotpCredentialRepository;
use crate::state::AppState;

use super::dto::{
    CompletarResetRequest, EstadoResponse, GenerarRequest, GenerarResponse, SolicitarResetRequest,
    VerificarTokenResponse,
};
use super::models::{MetodoMfa, RecoveryKit};
use super::repository::{PgRecoveryKitRepository, PgResetTokenRepository};
use super::service::RecoveryKitService;

type Servicio<'a> =
    RecoveryKitService<'a, PgRecoveryKitRepository, PgResetTokenRepository, PgUserRepository, PgTotpCredentialRepository, PgPreferenciasRepository>;

fn servicio(state: &AppState) -> Servicio<'_> {
    RecoveryKitService {
        kits: &state.recovery_kits,
        tokens: &state.recovery_reset_tokens,
        usuarios: &state.usuarios,
        totp: &state.mfa_totp,
        claves: &state.preferencias_usuario,
        secrets_key: &state.secrets_key,
        eventos: state.eventos.clone(),
    }
}

fn decodificar_b64(campo: &str, valor: &str) -> Result<Vec<u8>, ApiError> {
    B64.decode(valor).map_err(|_| DomainError::ValidacionInvalida(format!("{campo} no es base64 válido")).into())
}

fn kit_a_estado_response(kit: Option<RecoveryKit>) -> EstadoResponse {
    match kit {
        Some(k) => EstadoResponse { configured: true, created_at: Some(k.created_at), must_rotate: k.must_rotate },
        None => EstadoResponse { configured: false, created_at: None, must_rotate: false },
    }
}

pub async fn estado(State(state): State<AppState>, auth: AuthenticatedUser) -> Result<Json<EstadoResponse>, ApiError> {
    let kit = servicio(&state).estado(auth.user_id).await?;
    Ok(Json(kit_a_estado_response(kit)))
}

pub async fn generar_o_regenerar(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Json(req): Json<GenerarRequest>,
) -> Result<Json<GenerarResponse>, ApiError> {
    let clave = decodificar_b64("kit_public_key_x25519_b64", &req.kit_public_key_x25519_b64)?;
    let material = decodificar_b64("sealed_identity_material_b64", &req.sealed_identity_material_b64)?;
    let kit = servicio(&state).generar_o_regenerar(auth.user_id, clave, material).await?;
    Ok(Json(GenerarResponse { created_at: kit.created_at }))
}

/// `POST /recovery-kit/reset` — sin sesión, a propósito: cubre el caso
/// central de este flujo (alguien perdió la passphrase). Ver rate limit
/// dedicado en `lib.rs`.
pub async fn solicitar_reset(
    State(state): State<AppState>,
    Json(req): Json<SolicitarResetRequest>,
) -> Result<(), ApiError> {
    servicio(&state).solicitar_reset(&req.email).await?;
    Ok(())
}

pub async fn verificar_token(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<Json<VerificarTokenResponse>, ApiError> {
    let (material, metodo, email) = servicio(&state).verificar_token(&token).await?;
    Ok(Json(VerificarTokenResponse {
        sealed_identity_material_b64: B64.encode(material),
        mfa_method: match metodo {
            MetodoMfa::Totp => "totp",
            MetodoMfa::Email => "email",
        },
        email,
    }))
}

pub async fn enviar_codigo_email(State(state): State<AppState>, Path(token): Path<String>) -> Result<(), ApiError> {
    servicio(&state).enviar_codigo_email(&token).await?;
    Ok(())
}

pub async fn completar_reset(
    State(state): State<AppState>,
    Path(token): Path<String>,
    Json(req): Json<CompletarResetRequest>,
) -> Result<(), ApiError> {
    let blob = decodificar_b64("encrypted_private_key_blob_b64", &req.encrypted_private_key_blob_b64)?;
    let nonce = decodificar_b64("private_key_nonce_b64", &req.private_key_nonce_b64)?;
    let salt = decodificar_b64("kdf_salt_b64", &req.kdf_salt_b64)?;
    let nueva = NuevaClavePrivada { encrypted_private_key_blob: blob, private_key_nonce: nonce, kdf_salt: salt };

    servicio(&state).completar_reset(&token, &req.mfa_code, nueva).await?;
    Ok(())
}
