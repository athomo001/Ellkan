// Autor: Athan Espinoza

use axum::extract::{Path, State};
use axum::Json;
use uuid::Uuid;

use crate::auth::extractor::{AdminUser, AuthenticatedUser};
use crate::auth::repository::UserRepository;
use crate::b64;
use crate::error::{ApiError, DomainError};
use crate::state::AppState;

use super::dto::{
    AprobarRequest, ApprovalRequestResponse, DeviceApprovalPolicyResponse, MarcarConfiableRequest,
    SolicitarAprobacionRequest, TrustedDeviceResponse,
};
use super::models::{ApprovalRequest, DeviceApprovalPolicy, TrustedDevice};
use super::service::DeviceService;

type Servicio<'a> = DeviceService<
    'a,
    super::repository::PgTrustedDeviceRepository,
    super::repository::PgApprovalRequestRepository,
    super::repository::PgDeviceApprovalPolicyRepository,
    crate::auth::repository::PgSessionRepository,
    crate::auth::repository::PgUserRepository,
>;

fn servicio(state: &AppState) -> Servicio<'_> {
    DeviceService {
        confiables: &state.dispositivos_confiables,
        solicitudes: &state.solicitudes_aprobacion,
        policy: &state.politica_aprobacion_dispositivo,
        sesiones: &state.sesiones,
        usuarios: &state.usuarios,
    }
}

fn a_response(d: TrustedDevice) -> TrustedDeviceResponse {
    TrustedDeviceResponse { id: d.id, label: d.label, created_at: d.created_at, revoked_at: d.revoked_at }
}

fn solicitud_a_response(s: ApprovalRequest, incluir_sellado: bool) -> ApprovalRequestResponse {
    ApprovalRequestResponse {
        id: s.id,
        fingerprint: s.fingerprint,
        status: s.status,
        session_id: s.session_id,
        sealed_user_private_key_b64: if incluir_sellado {
            s.sealed_user_private_key.map(|k| b64::encode(&k))
        } else {
            None
        },
    }
}

pub async fn listar_confiables(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
) -> Result<Json<Vec<TrustedDeviceResponse>>, ApiError> {
    let dispositivos = servicio(&state).listar_confiables(auth.user_id).await?;
    Ok(Json(dispositivos.into_iter().map(a_response).collect()))
}

pub async fn marcar_confiable(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Json(req): Json<MarcarConfiableRequest>,
) -> Result<Json<TrustedDeviceResponse>, ApiError> {
    let public_key = b64::decode(&req.device_public_key_b64)
        .map_err(|_| DomainError::ValidacionInvalida("device_public_key_b64 inválido".into()))?;
    let sealed = b64::decode(&req.sealed_user_private_key_b64)
        .map_err(|_| DomainError::ValidacionInvalida("sealed_user_private_key_b64 inválido".into()))?;

    let dispositivo = servicio(&state)
        .marcar_confiable(auth.user_id, &public_key, &sealed, req.label.as_deref())
        .await?;
    Ok(Json(a_response(dispositivo)))
}

pub async fn revocar(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path(device_id): Path<Uuid>,
) -> Result<(), ApiError> {
    servicio(&state).revocar(auth.user_id, device_id).await?;
    Ok(())
}

pub async fn listar_pendientes(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
) -> Result<Json<Vec<ApprovalRequestResponse>>, ApiError> {
    let pendientes = servicio(&state).listar_pendientes(auth.user_id).await?;
    Ok(Json(pendientes.into_iter().map(|s| solicitud_a_response(s, false)).collect()))
}

pub async fn solicitar_aprobacion(
    State(state): State<AppState>,
    Json(req): Json<SolicitarAprobacionRequest>,
) -> Result<Json<ApprovalRequestResponse>, ApiError> {
    let public_key = b64::decode(&req.device_public_key_b64)
        .map_err(|_| DomainError::ValidacionInvalida("device_public_key_b64 inválido".into()))?;

    let usuario = state
        .usuarios
        .buscar_por_email(&req.email)
        .await
        .map_err(DomainError::from)?
        .ok_or(DomainError::InvalidCredentials)?;

    let solicitud = servicio(&state).solicitar_aprobacion(usuario.id, &public_key).await?;
    Ok(Json(solicitud_a_response(solicitud, false)))
}

pub async fn estado_aprobacion(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApprovalRequestResponse>, ApiError> {
    let solicitud = servicio(&state).estado_aprobacion(id).await?;
    let aprobada = solicitud.status == "approved";
    Ok(Json(solicitud_a_response(solicitud, aprobada)))
}

pub async fn aprobar(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path(id): Path<Uuid>,
    Json(req): Json<AprobarRequest>,
) -> Result<(), ApiError> {
    let sellado = b64::decode(&req.sealed_user_private_key_b64)
        .map_err(|_| DomainError::ValidacionInvalida("sealed_user_private_key_b64 inválido".into()))?;
    servicio(&state).aprobar(auth.user_id, id, &sellado).await?;
    Ok(())
}

pub async fn politica(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<DeviceApprovalPolicyResponse>, ApiError> {
    let p = servicio(&state).politica().await?;
    Ok(Json(DeviceApprovalPolicyResponse {
        allow_peer_device_approval: p.allow_peer_device_approval,
        allow_admin_device_approval: p.allow_admin_device_approval,
    }))
}

pub async fn actualizar_politica(
    State(state): State<AppState>,
    _admin: AdminUser,
    Json(req): Json<DeviceApprovalPolicyResponse>,
) -> Result<(), ApiError> {
    servicio(&state)
        .actualizar_politica(DeviceApprovalPolicy {
            allow_peer_device_approval: req.allow_peer_device_approval,
            allow_admin_device_approval: req.allow_admin_device_approval,
        })
        .await?;
    Ok(())
}
