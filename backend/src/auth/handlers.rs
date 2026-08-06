// Autor: Athan Espinoza

use axum::extract::{Path, State};
use axum::Json;

use crate::b64;
use crate::error::{ApiError, DomainError};
use crate::state::AppState;

use super::dto::{
    ChallengeRequest, ChallengeResponse, KeyMaterialRequest, KeyMaterialResponse, PublicKeyResponse,
    RegisterRequest, RegisterResponse, ServerKeyResponse, VerifyDeviceRequest, VerifyRequest, VerifyResponse,
};
use super::extractor::AuthenticatedUser;
use super::models::{NuevoUsuario, ResultadoVerify};
use super::repository::UserRepository;
use super::service::AuthService;

#[allow(clippy::type_complexity)]
fn servicio(
    state: &AppState,
) -> AuthService<
    '_,
    super::repository::PgUserRepository,
    super::repository::PgAuthChallengeRepository,
    super::repository::PgSessionRepository,
    super::repository::PgKnownDeviceRepository,
    super::repository::PgDeviceChallengeRepository,
    crate::mfa::repository::PgMfaPolicyRepository,
    crate::mfa::repository::PgTotpCredentialRepository,
    crate::mfa::repository::PgMfaChallengeRepository,
> {
    AuthService {
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

/// Mismo shape de respuesta para `verify` y `verify_device` — desde F-14 los
/// dos pueden resolver en cualquiera de los cuatro estados.
fn resultado_a_response(resultado: ResultadoVerify) -> VerifyResponse {
    match resultado {
        ResultadoVerify::SesionCompleta(sesion) => VerifyResponse {
            estado: "completo",
            session_id: Some(sesion.id),
            user_id: Some(sesion.user_id),
            device_challenge_id: None,
        },
        ResultadoVerify::PendienteDispositivo { device_challenge_id } => VerifyResponse {
            estado: "pendiente_dispositivo",
            session_id: None,
            user_id: None,
            device_challenge_id: Some(device_challenge_id),
        },
        ResultadoVerify::PendienteMfa { session_id } => VerifyResponse {
            estado: "pendiente_mfa",
            session_id: Some(session_id),
            user_id: None,
            device_challenge_id: None,
        },
        ResultadoVerify::RequiereConfigurarMfa { session_id } => VerifyResponse {
            estado: "requiere_configurar_mfa",
            session_id: Some(session_id),
            user_id: None,
            device_challenge_id: None,
        },
    }
}

pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, ApiError> {
    let publica_x25519 =
        b64::decode(&req.public_key_x25519_b64).map_err(|_| DomainError::ValidacionInvalida("public_key_x25519_b64 inválido".into()))?;
    let publica_ed25519 = b64::decode(&req.public_key_ed25519_b64)
        .map_err(|_| DomainError::ValidacionInvalida("public_key_ed25519_b64 inválido".into()))?;
    let blob = b64::decode(&req.encrypted_private_key_blob_b64)
        .map_err(|_| DomainError::ValidacionInvalida("encrypted_private_key_blob_b64 inválido".into()))?;
    let nonce = b64::decode(&req.private_key_nonce_b64)
        .map_err(|_| DomainError::ValidacionInvalida("private_key_nonce_b64 inválido".into()))?;
    let salt = b64::decode(&req.kdf_salt_b64)
        .map_err(|_| DomainError::ValidacionInvalida("kdf_salt_b64 inválido".into()))?;

    let nuevo = NuevoUsuario {
        email: &req.email,
        display_name: &req.display_name,
        public_key_x25519: &publica_x25519,
        public_key_ed25519: &publica_ed25519,
        encrypted_private_key_blob: &blob,
        private_key_nonce: &nonce,
        kdf_salt: &salt,
    };

    let usuario = servicio(&state).registrar(nuevo).await?;
    Ok(Json(RegisterResponse { user_id: usuario.id }))
}

pub async fn server_key(State(state): State<AppState>) -> Json<ServerKeyResponse> {
    Json(ServerKeyResponse {
        public_key_ed25519_b64: b64::encode(state.server_public_key_ed25519.as_slice()),
    })
}

pub async fn challenge(
    State(state): State<AppState>,
    Json(req): Json<ChallengeRequest>,
) -> Result<Json<ChallengeResponse>, ApiError> {
    let nonce = servicio(&state).challenge(&req.email).await?;
    Ok(Json(ChallengeResponse { nonce_b64: b64::encode(&nonce) }))
}

pub async fn key_material(
    State(state): State<AppState>,
    Json(req): Json<KeyMaterialRequest>,
) -> Result<Json<KeyMaterialResponse>, ApiError> {
    let material = servicio(&state).material_desbloqueo(&req.email).await?;
    Ok(Json(KeyMaterialResponse {
        encrypted_private_key_blob_b64: b64::encode(&material.encrypted_private_key_blob),
        private_key_nonce_b64: b64::encode(&material.private_key_nonce),
        kdf_salt_b64: b64::encode(&material.kdf_salt),
    }))
}

pub async fn verify(
    State(state): State<AppState>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, ApiError> {
    let nonce = b64::decode(&req.nonce_b64)
        .map_err(|_| DomainError::ValidacionInvalida("nonce_b64 inválido".into()))?;
    let firma = b64::decode(&req.signature_b64)
        .map_err(|_| DomainError::ValidacionInvalida("signature_b64 inválido".into()))?;
    let device_token_hash = b64::decode(&req.device_token_hash_b64)
        .map_err(|_| DomainError::ValidacionInvalida("device_token_hash_b64 inválido".into()))?;

    let resultado = servicio(&state).verify(&req.email, &nonce, &firma, &device_token_hash).await?;
    Ok(Json(resultado_a_response(resultado)))
}

pub async fn verify_device(
    State(state): State<AppState>,
    Json(req): Json<VerifyDeviceRequest>,
) -> Result<Json<VerifyResponse>, ApiError> {
    let resultado = servicio(&state).verify_device(req.device_challenge_id, &req.code).await?;
    Ok(Json(resultado_a_response(resultado)))
}

pub async fn logout(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
) -> Result<(), ApiError> {
    servicio(&state).logout(auth.session_id, auth.user_id).await?;
    Ok(())
}

pub async fn public_key(
    State(state): State<AppState>,
    Path(email): Path<String>,
    _auth: AuthenticatedUser,
) -> Result<Json<PublicKeyResponse>, ApiError> {
    let usuario = state
        .usuarios
        .buscar_por_email(&email)
        .await
        .map_err(DomainError::from)?
        .ok_or(DomainError::NotFound)?;
    let keys = state
        .usuarios
        .buscar_keys(usuario.id)
        .await
        .map_err(DomainError::from)?
        .ok_or(DomainError::NotFound)?;

    Ok(Json(PublicKeyResponse {
        user_id: usuario.id,
        public_key_x25519_b64: b64::encode(&keys.public_key_x25519),
    }))
}
