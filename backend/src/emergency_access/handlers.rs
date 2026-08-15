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
    ActualizarPoliticaRequest, DesignarRequest, EmergencyAccessPolicyResponse, EmergencyAccessResponse,
};
use super::models::EmergencyAccess;
use super::repository::{
    PgEmergencyAccessPolicyRepository, PgEmergencyAccessRepository, PgEmergencyAccessRequestRepository,
};
use super::service::EmergencyAccessService;

type Servicio<'a> = EmergencyAccessService<
    'a,
    PgEmergencyAccessPolicyRepository,
    PgEmergencyAccessRepository,
    PgEmergencyAccessRequestRepository,
>;

fn servicio(state: &AppState) -> Servicio<'_> {
    EmergencyAccessService {
        policy: &state.emergency_access_policy,
        accesos: &state.emergency_access,
        requests: &state.emergency_access_requests,
        eventos: state.eventos.clone(),
    }
}

fn a_response(
    acceso: EmergencyAccess,
    request_status: Option<String>,
    material_b64: Option<String>,
) -> EmergencyAccessResponse {
    EmergencyAccessResponse {
        id: acceso.id,
        granter_id: acceso.granter_id,
        grantee_id: acceso.grantee_id,
        access_level: acceso.access_level,
        wait_time_days: acceso.wait_time_days,
        status: acceso.status,
        request_status,
        sealed_material_b64: material_b64,
        created_at: acceso.created_at,
    }
}

pub async fn politica(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<EmergencyAccessPolicyResponse>, ApiError> {
    let habilitado = servicio(&state).politica().await?;
    Ok(Json(EmergencyAccessPolicyResponse { enabled: habilitado }))
}

pub async fn actualizar_politica(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(req): Json<ActualizarPoliticaRequest>,
) -> Result<Json<EmergencyAccessPolicyResponse>, ApiError> {
    servicio(&state).actualizar_politica(admin.user_id, req.enabled).await?;
    Ok(Json(EmergencyAccessPolicyResponse { enabled: req.enabled }))
}

pub async fn listar(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
) -> Result<Json<Vec<EmergencyAccessResponse>>, ApiError> {
    let filas = servicio(&state).listar(auth.user_id).await?;
    Ok(Json(
        filas
            .into_iter()
            .map(|(acceso, estado, puede_leer)| {
                let material = if puede_leer { Some(B64.encode(&acceso.sealed_material)) } else { None };
                a_response(acceso, estado, material)
            })
            .collect(),
    ))
}

pub async fn designar(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Json(req): Json<DesignarRequest>,
) -> Result<Json<EmergencyAccessResponse>, ApiError> {
    let sellado = B64
        .decode(&req.sealed_material_b64)
        .map_err(|_| ApiError::from(DomainError::ValidacionInvalida("sealed_material_b64 inválido".into())))?;
    let acceso = servicio(&state)
        .designar(auth.user_id, req.grantee_id, &req.access_level, sellado, req.wait_time_days)
        .await?;
    Ok(Json(a_response(acceso, None, None)))
}

pub async fn aceptar(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Result<(), ApiError> {
    servicio(&state).aceptar(auth.user_id, id).await?;
    Ok(())
}

pub async fn revocar(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Result<(), ApiError> {
    servicio(&state).revocar(auth.user_id, id).await?;
    Ok(())
}

pub async fn solicitar(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Result<(), ApiError> {
    servicio(&state).solicitar(auth.user_id, id).await?;
    Ok(())
}

pub async fn aprobar(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Result<(), ApiError> {
    servicio(&state).aprobar(auth.user_id, id).await?;
    Ok(())
}

pub async fn rechazar(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Result<(), ApiError> {
    servicio(&state).rechazar(auth.user_id, id).await?;
    Ok(())
}
