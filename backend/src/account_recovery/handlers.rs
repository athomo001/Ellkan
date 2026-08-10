// Autor: Athan Espinoza

use axum::extract::{Path, State};
use axum::Json;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use uuid::Uuid;

use crate::auth::extractor::{AdminUser, AuthenticatedUser};
use crate::error::{ApiError, DomainError};
use crate::state::AppState;

use super::dto::{
    ActualizarAccountRecoveryPolicyRequest, AccountRecoveryPolicyResponse, CompletarSolicitudRequest,
    CrearSolicitudRequest, EnrolarRequest, EscrowResponse, MiEstadoResponse, OrgPublicKeyResponse,
    SolicitudAdminResponse, SolicitudResponse,
};
use super::models::{AccountRecoveryPolicy, Escrow, RecoveryRequest, SolicitudPendiente};
use super::repository::{
    PgAccountRecoveryPolicyRepository, PgEscrowRepository, PgOrgRecoveryKeyRepository,
    PgRecoveryRequestRepository,
};
use super::service::AccountRecoveryService;
use crate::auth::repository::PgUserRepository;
use crate::me::models::NuevaClavePrivada;
use crate::me::repository::PgPreferenciasRepository;

type Servicio<'a> = AccountRecoveryService<
    'a,
    PgAccountRecoveryPolicyRepository,
    PgOrgRecoveryKeyRepository,
    PgEscrowRepository,
    PgRecoveryRequestRepository,
    PgUserRepository,
    PgPreferenciasRepository,
>;

fn servicio(state: &AppState) -> Servicio<'_> {
    AccountRecoveryService {
        policy: &state.account_recovery_policy,
        org_key: &state.org_recovery_key,
        escrow: &state.account_recovery_escrow,
        requests: &state.account_recovery_requests,
        usuarios: &state.usuarios,
        claves: &state.preferencias_usuario,
        secrets_key: &state.secrets_key,
        pool: &state.pool,
        eventos: state.eventos.clone(),
    }
}

fn decodificar_b64(campo: &str, valor: &str) -> Result<Vec<u8>, ApiError> {
    B64.decode(valor)
        .map_err(|_| DomainError::ValidacionInvalida(format!("{campo} no es base64 válido")).into())
}

fn politica_a_response(p: AccountRecoveryPolicy) -> AccountRecoveryPolicyResponse {
    AccountRecoveryPolicyResponse {
        required: p.required,
        grace_period_days: p.grace_period_days,
        default_approval_threshold: p.default_approval_threshold,
    }
}

fn escrow_a_response(e: Escrow) -> EscrowResponse {
    EscrowResponse { id: e.id, created_at: e.created_at }
}

fn solicitud_a_response(r: RecoveryRequest) -> SolicitudResponse {
    SolicitudResponse {
        id: r.id,
        status: r.status,
        approvals_count: r.approvals.as_array().map(|a| a.len()).unwrap_or(0),
        sealed_private_key_for_requester_b64: r.sealed_private_key_for_requester.map(|b| B64.encode(b)),
    }
}

pub async fn politica(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<AccountRecoveryPolicyResponse>, ApiError> {
    let p = servicio(&state).politica().await?;
    Ok(Json(politica_a_response(p)))
}

pub async fn actualizar_politica(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(req): Json<ActualizarAccountRecoveryPolicyRequest>,
) -> Result<Json<AccountRecoveryPolicyResponse>, ApiError> {
    let p = servicio(&state)
        .actualizar_politica(admin.user_id, req.required, req.grace_period_days, req.default_approval_threshold)
        .await?;
    Ok(Json(politica_a_response(p)))
}

pub async fn mi_estado(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
) -> Result<Json<MiEstadoResponse>, ApiError> {
    let enrolled = servicio(&state).mi_estado(auth.user_id).await?;
    Ok(Json(MiEstadoResponse { enrolled }))
}

pub async fn org_public_key(
    State(state): State<AppState>,
    _auth: AuthenticatedUser,
) -> Result<Json<OrgPublicKeyResponse>, ApiError> {
    let publica = servicio(&state).obtener_org_public_key().await?;
    Ok(Json(OrgPublicKeyResponse { public_key_x25519_b64: B64.encode(publica) }))
}

pub async fn enrolar(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Json(req): Json<EnrolarRequest>,
) -> Result<Json<EscrowResponse>, ApiError> {
    let sellado = decodificar_b64("sealed_private_key_for_org_b64", &req.sealed_private_key_for_org_b64)?;
    let escrow = servicio(&state).enrolar(auth.user_id, sellado).await?;
    Ok(Json(escrow_a_response(escrow)))
}

/// `POST /account-recovery/requests` — sin sesión, a propósito (ver
/// `AccountRecoveryService::crear_solicitud`).
pub async fn crear_solicitud(
    State(state): State<AppState>,
    Json(req): Json<CrearSolicitudRequest>,
) -> Result<Json<SolicitudResponse>, ApiError> {
    let clave = decodificar_b64("requester_public_key_x25519_b64", &req.requester_public_key_x25519_b64)?;
    let solicitud = servicio(&state).crear_solicitud(&req.email, clave).await?;
    Ok(Json(solicitud_a_response(solicitud)))
}

/// `GET /account-recovery/requests/{id}` — poll sin sesión, mismo criterio
/// que `GET /auth/device-approval/{id}` (F-37): sin esto no hay forma de
/// que el cliente que perdió su passphrase se entere de que ya lo aprobaron.
pub async fn estado_solicitud(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<SolicitudResponse>, ApiError> {
    let solicitud = servicio(&state).estado_solicitud(id).await?;
    Ok(Json(solicitud_a_response(solicitud)))
}

pub async fn aprobar(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<Uuid>,
) -> Result<Json<SolicitudResponse>, ApiError> {
    let solicitud = servicio(&state).aprobar(admin.user_id, id).await?;
    Ok(Json(solicitud_a_response(solicitud)))
}

pub async fn completar(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(req): Json<CompletarSolicitudRequest>,
) -> Result<(), ApiError> {
    let blob = decodificar_b64("encrypted_private_key_blob_b64", &req.encrypted_private_key_blob_b64)?;
    let nonce = decodificar_b64("private_key_nonce_b64", &req.private_key_nonce_b64)?;
    let salt = decodificar_b64("kdf_salt_b64", &req.kdf_salt_b64)?;
    let nueva = NuevaClavePrivada { encrypted_private_key_blob: blob, private_key_nonce: nonce, kdf_salt: salt };

    servicio(&state).completar(id, nueva).await?;
    Ok(())
}

fn solicitud_admin_a_response(s: SolicitudPendiente) -> SolicitudAdminResponse {
    SolicitudAdminResponse {
        id: s.id,
        target_email: s.target_email,
        status: s.status,
        approvals_count: s.approvals.as_array().map(|a| a.len()).unwrap_or(0),
        approval_threshold: s.approval_threshold,
        created_at: s.created_at,
    }
}

/// `GET /admin/account-recovery/requests` — descubribilidad para el admin,
/// ver `AccountRecoveryService::listar_pendientes`.
pub async fn listar_solicitudes_pendientes(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<Vec<SolicitudAdminResponse>>, ApiError> {
    let solicitudes = servicio(&state).listar_pendientes().await?;
    Ok(Json(solicitudes.into_iter().map(solicitud_admin_a_response).collect()))
}
