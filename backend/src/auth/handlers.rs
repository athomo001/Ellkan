// Autor: Athan Espinoza

use axum::extract::{Path, Query, State};
use axum::http::header;
use axum::response::IntoResponse;
use axum::Json;
use uuid::Uuid;

use crate::b64;
use crate::error::{ApiError, DomainError};
use crate::me::service::AvatarService;
use crate::state::AppState;

use super::dto::{
    ChallengeRequest, ChallengeResponse, KeyMaterialRequest, KeyMaterialResponse, PublicKeyResponse,
    RegisterRequest, RegisterResponse, ResendVerificationRequest, ServerKeyResponse, VerifyDeviceRequest,
    VerifyEmailRequest, VerifyRequest, VerifyResponse,
};
use super::extractor::{AdminUser, AuthenticatedUser};
use super::models::{NuevoUsuario, ResultadoRegistro, ResultadoVerify};
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
    crate::smtp_config::repository::PgSmtpConfigRepository,
    crate::self_registration::repository::PgSelfRegistrationPolicyRepository,
    super::repository::PgUserRepository,
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
        smtp_config: &state.smtp_config,
        self_registration: &state.self_registration_policy,
        email_verification: &state.usuarios,
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

    let resultado = servicio(&state).registrar(nuevo).await?;
    let (user_id, pending_verification) = match resultado {
        ResultadoRegistro::Completo(usuario) => (usuario.id, false),
        ResultadoRegistro::PendienteVerificacion { user_id } => (user_id, true),
    };
    Ok(Json(RegisterResponse { user_id, pending_verification }))
}

/// `POST /admin/users` — ver `AuthService::crear_por_admin`. Mismo body que
/// el registro público (`RegisterRequest`), la ceremonia de claves la sigue
/// corriendo el navegador del admin.
pub async fn crear_admin(
    State(state): State<AppState>,
    _admin: AdminUser,
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

    let usuario = servicio(&state).crear_por_admin(nuevo).await?;
    Ok(Json(RegisterResponse { user_id: usuario.id, pending_verification: false }))
}

pub async fn verify_email(State(state): State<AppState>, Json(req): Json<VerifyEmailRequest>) -> Result<(), ApiError> {
    servicio(&state).verificar_email(&req.email, &req.code).await?;
    Ok(())
}

pub async fn resend_verification(
    State(state): State<AppState>,
    Json(req): Json<ResendVerificationRequest>,
) -> Result<(), ApiError> {
    servicio(&state).reenviar_verificacion(&req.email).await?;
    Ok(())
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
    auth: AuthenticatedUser,
) -> Result<Json<PublicKeyResponse>, ApiError> {
    let usuario = state
        .usuarios
        .buscar_por_email_visible(auth.user_id, &email)
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

/// `GET /users/{id}/avatar` — hallazgo real de uso 2026-08-11: el buscador
/// de destinatarios del modal de compartir (`GET /users/search`, cualquier
/// miembro autenticado) sólo tenía un ícono genérico porque no había forma
/// de pedir el avatar de OTRO usuario sin ser admin (`GET /admin/users/{id}/avatar`
/// exige `AdminUser`). Mismo servicio (`AvatarService`, ya genérico en
/// `user_id`), mismo nivel de exposición que `GET /users/search`/`GET
/// /users/{email}/public-key` (cualquier miembro autenticado puede ver el
/// directorio básico de la organización, el avatar no es más sensible que
/// el email o el nombre ya expuestos ahí).
pub async fn avatar(
    State(state): State<AppState>,
    _auth: AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let avatar = AvatarService { avatar: &state.preferencias_usuario }.obtener(id).await?;
    match avatar {
        Some(a) => Ok(([(header::CONTENT_TYPE, a.content_type)], a.bytes).into_response()),
        None => Err(ApiError::from(DomainError::NotFound)),
    }
}

const LIMITE_BUSQUEDA: i64 = 10;

/// `GET /users/search?q=` — buscador en vivo del modal de compartir, mismo
/// criterio de "cualquier miembro de la org puede buscar a otro" que ya
/// aplica `public_key` (email exacto) — sólo agrega coincidencia parcial.
pub async fn buscar(
    State(state): State<AppState>,
    Query(query): Query<super::dto::BuscarUsuariosQuery>,
    auth: AuthenticatedUser,
) -> Result<Json<Vec<super::dto::UsuarioBusquedaResponse>>, ApiError> {
    if query.q.trim().len() < 2 {
        return Ok(Json(Vec::new()));
    }
    let resultados = state
        .usuarios
        .buscar_por_prefijo(auth.user_id, query.q.trim(), LIMITE_BUSQUEDA)
        .await
        .map_err(DomainError::from)?;
    Ok(Json(
        resultados
            .into_iter()
            .map(|u| super::dto::UsuarioBusquedaResponse {
                user_id: u.id,
                email: u.email,
                display_name: u.display_name,
                public_key_x25519_b64: b64::encode(&u.public_key_x25519),
                has_avatar: u.has_avatar,
            })
            .collect(),
    ))
}
