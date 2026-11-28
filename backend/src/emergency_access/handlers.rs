// Autor: Athan Espinoza

use axum::Json;
use axum::extract::{Path, State};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use uuid::Uuid;

use crate::auth::extractor::{AdminUser, AuthenticatedUser};
use crate::error::ApiError;
use crate::state::AppState;

use super::dto::{ActualizarPoliticaRequest, BovedaTitularResponse, DesignarRequest, RecursoTitularResponse, EmergencyAccessPolicyResponse, EmergencyAccessResponse, PersonaResponse};
use super::models::EmergencyAccess;
use super::repository::{PgEmergencyAccessPolicyRepository, PgEmergencyAccessRepository, PgEmergencyAccessRequestRepository};
use super::service::EmergencyAccessService;

type Servicio<'a> =
    EmergencyAccessService<'a, PgEmergencyAccessPolicyRepository, PgEmergencyAccessRepository, PgEmergencyAccessRequestRepository>;

fn servicio(state: &AppState) -> Servicio<'_> {
    EmergencyAccessService {
        policy: &state.emergency_access_policy,
        accesos: &state.emergency_access,
        requests: &state.emergency_access_requests,
        eventos: state.eventos.clone(),
    }
}

fn a_response(acceso: EmergencyAccess, request_status: Option<String>, material_b64: Option<String>) -> EmergencyAccessResponse {
    EmergencyAccessResponse {
        id: acceso.id,
        granter_id: acceso.granter_id,
        grantee_id: acceso.grantee_id,
        granter: PersonaResponse::default(),
        grantee: PersonaResponse::default(),
        access_level: acceso.access_level,
        wait_time_days: acceso.wait_time_days,
        status: acceso.status,
        request_status,
        sealed_material_b64: material_b64,
        created_at: acceso.created_at,
    }
}

pub async fn politica(State(state): State<AppState>, _admin: AdminUser) -> Result<Json<EmergencyAccessPolicyResponse>, ApiError> {
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

pub async fn listar(State(state): State<AppState>, auth: AuthenticatedUser) -> Result<Json<Vec<EmergencyAccessResponse>>, ApiError> {
    let filas = servicio(&state).listar(auth.user_id).await?;
    let personas: std::collections::HashMap<Uuid, PersonaResponse> = servicio(&state)
        .personas_relacionadas(auth.user_id)
        .await?
        .into_iter()
        .map(|p| (p.id, PersonaResponse { email: p.email, display_name: p.display_name }))
        .collect();
    let persona = |id: Uuid| {
        personas
            .get(&id)
            .map(|p| PersonaResponse { email: p.email.clone(), display_name: p.display_name.clone() })
    };
    Ok(Json(
        filas
            .into_iter()
            .map(|(acceso, estado, puede_leer)| {
                let material = if puede_leer {
                    Some(B64.encode(&acceso.sealed_material))
                } else {
                    None
                };
                let (granter, grantee) = (persona(acceso.granter_id), persona(acceso.grantee_id));
                let mut resp = a_response(acceso, estado, material);
                // La propia persona no viene en `personas_relacionadas`: queda vacía
                // y la pantalla la muestra como "vos".
                resp.granter = granter.unwrap_or_default();
                resp.grantee = grantee.unwrap_or_default();
                resp
            })
            .collect(),
    ))
}

pub async fn designar(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Json(req): Json<DesignarRequest>,
) -> Result<Json<EmergencyAccessResponse>, ApiError> {
    // QA-45: el material son las claves privadas del titular selladas (unos
    // 112 bytes); 4 KiB deja margen para otro formato sin aceptar basura.
    let sellado = crate::validacion::b64_acotado(&req.sealed_material_b64, "sealed_material_b64", 4096)?;
    let acceso = servicio(&state)
        .designar(auth.user_id, req.grantee_id, &req.access_level, sellado, req.wait_time_days)
        .await?;
    Ok(Json(a_response(acceso, None, None)))
}

pub async fn aceptar(State(state): State<AppState>, auth: AuthenticatedUser, Path(id): Path<Uuid>) -> Result<(), ApiError> {
    servicio(&state).aceptar(auth.user_id, id).await?;
    Ok(())
}

pub async fn revocar(State(state): State<AppState>, auth: AuthenticatedUser, Path(id): Path<Uuid>) -> Result<(), ApiError> {
    servicio(&state).revocar(auth.user_id, id).await?;
    Ok(())
}

pub async fn solicitar(State(state): State<AppState>, auth: AuthenticatedUser, Path(id): Path<Uuid>) -> Result<(), ApiError> {
    servicio(&state).solicitar(auth.user_id, id).await?;
    Ok(())
}

pub async fn aprobar(State(state): State<AppState>, auth: AuthenticatedUser, Path(id): Path<Uuid>) -> Result<(), ApiError> {
    servicio(&state).aprobar(auth.user_id, id).await?;
    Ok(())
}

pub async fn rechazar(State(state): State<AppState>, auth: AuthenticatedUser, Path(id): Path<Uuid>) -> Result<(), ApiError> {
    servicio(&state).rechazar(auth.user_id, id).await?;
    Ok(())
}

/// F-36 (#134): la bóveda del titular, sólo lectura y auditada.
pub async fn boveda(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Result<Json<BovedaTitularResponse>, ApiError> {
    let (acceso, recursos) = servicio(&state).boveda(auth.user_id, id).await?;
    let granter = servicio(&state)
        .personas_relacionadas(auth.user_id)
        .await?
        .into_iter()
        .find(|p| p.id == acceso.granter_id)
        .map(|p| PersonaResponse { email: p.email, display_name: p.display_name })
        .unwrap_or_default();
    Ok(Json(BovedaTitularResponse {
        granter_id: acceso.granter_id,
        granter,
        access_level: acceso.access_level,
        sealed_material_b64: B64.encode(&acceso.sealed_material),
        resources: recursos
            .into_iter()
            .map(|r| RecursoTitularResponse {
                id: r.id,
                created_by: r.created_by,
                resource_type_slug: r.resource_type_slug,
                metadata_ciphertext_b64: B64.encode(&r.metadata_ciphertext),
                metadata_nonce_b64: B64.encode(&r.metadata_nonce),
                metadata_key_type: r.metadata_key_type,
                metadata_key_id: r.metadata_key_id,
                metadata_sealed_key_b64: r.metadata_sealed_key.as_deref().map(|k| B64.encode(k)),
                sealed_dek_b64: B64.encode(&r.sealed_dek),
                secret_ciphertext_b64: B64.encode(&r.secret_ciphertext),
                secret_nonce_b64: B64.encode(&r.secret_nonce),
                updated_at: r.updated_at,
            })
            .collect(),
    }))
}

/// F-36 (#134): `POST /me/emergency-access/{id}/takeover`. Mismo cuerpo que
/// `POST /me/change-passphrase`: el blob del titular re-sellado con la
/// passphrase nueva y la prueba de posesión firmada con su Ed25519 sobre un
/// desafío emitido para su correo. Al aplicarse rota el `security_stamp` del
/// titular (se cierran sus sesiones). Sólo con nivel `takeover`.
pub async fn takeover(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path(id): Path<Uuid>,
    Json(req): Json<crate::me::dto::CambiarPassphraseRequest>,
) -> Result<axum::http::StatusCode, ApiError> {
    let servicio = servicio(&state);
    let acceso = servicio.autorizar_takeover(auth.user_id, id).await?;
    let (nueva, prueba) = crate::me::handlers::reemplazo_desde(&req)?;
    let verificado = crate::me::service::verificar_posesion(&state.usuarios, &state.challenges, acceso.granter_id, nueva, &prueba).await?;
    crate::me::service::CambiarPassphraseService { claves: &state.preferencias_usuario, eventos: state.eventos.clone() }
        .actualizar(verificado)
        .await?;
    servicio.registrar_takeover(auth.user_id, &acceso);
    Ok(axum::http::StatusCode::NO_CONTENT)
}
