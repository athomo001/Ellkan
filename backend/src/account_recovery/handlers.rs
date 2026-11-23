// Autor: Athan Espinoza

use axum::Json;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use uuid::Uuid;

use crate::auth::extractor::{AdminUser, AuthenticatedUser};
use crate::error::{ApiError, DomainError};
use crate::state::AppState;

use super::dto::{
    AccountRecoveryPolicyResponse, ActualizarAccountRecoveryPolicyRequest, AgregarCustodioRequest, CompletarSolicitudRequest,
    ConfirmarSolicitudRequest, ConfirmarSolicitudResponse, CrearClaveOrgRequest, CrearClaveOrgResponse, CrearSolicitudRequest,
    CustodioPendienteResponse, EjecutarRequest, EnrolarRequest, EscrowResponse, EstadoCustodiaResponse, MaterialCustodioResponse,
    MiEstadoResponse, OrgPublicKeyResponse, PurgaResponse, SolicitudAdminResponse, SolicitudResponse,
};
use super::models::{AccountRecoveryPolicy, CustodioPendiente, Escrow, OrgRecoveryKey, RecoveryRequest, SolicitudPendiente};
use super::repository::{PgAccountRecoveryPolicyRepository, PgEscrowRepository, PgOrgRecoveryKeyRepository, PgRecoveryRequestRepository};
use super::service::AccountRecoveryService;
use crate::admin::repository::PgRoleRepository;
use crate::auth::repository::{PgAuthChallengeRepository, PgUserRepository};
use crate::groups::repository::PgGroupMemberRepository;
use crate::me::models::NuevaClavePrivada;
use crate::me::repository::PgPreferenciasRepository;
use crate::me::service::PruebaDePosesion;

type Servicio<'a> = AccountRecoveryService<
    'a,
    PgAccountRecoveryPolicyRepository,
    PgOrgRecoveryKeyRepository,
    PgEscrowRepository,
    PgRecoveryRequestRepository,
    PgUserRepository,
    PgPreferenciasRepository,
    PgRoleRepository,
    PgGroupMemberRepository,
    PgAuthChallengeRepository,
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
        roles: &state.roles,
        grupos: &state.miembros_de_grupo,
        challenges: &state.challenges,
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

pub async fn politica(State(state): State<AppState>, _admin: AdminUser) -> Result<Json<AccountRecoveryPolicyResponse>, ApiError> {
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

pub async fn mi_estado(State(state): State<AppState>, auth: AuthenticatedUser) -> Result<Json<MiEstadoResponse>, ApiError> {
    let e = servicio(&state).mi_estado(auth.user_id).await?;
    Ok(Json(MiEstadoResponse {
        enrolled: e.enrolled,
        org_recovery_key_id: e.org_recovery_key_id,
        current_org_recovery_key_id: e.current_org_recovery_key_id,
    }))
}

fn clave_a_response(k: OrgRecoveryKey) -> OrgPublicKeyResponse {
    OrgPublicKeyResponse {
        id: k.id,
        public_key_x25519_b64: B64.encode(k.public_key_x25519),
        custody: k.custodia.as_str(),
        created_at: k.created_at,
    }
}

/// `GET /account-recovery/org-public-key` — 404 si la organización todavía
/// no generó su clave (QA-09: el servidor ya no la crea solo).
pub async fn org_public_key(State(state): State<AppState>, _auth: AuthenticatedUser) -> Result<Json<OrgPublicKeyResponse>, ApiError> {
    let clave = servicio(&state).org_key_vigente().await?;
    Ok(Json(clave_a_response(clave)))
}

pub async fn enrolar(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Json(req): Json<EnrolarRequest>,
) -> Result<Json<EscrowResponse>, ApiError> {
    let sellado = decodificar_b64("sealed_private_key_for_org_b64", &req.sealed_private_key_for_org_b64)?;
    let escrow = servicio(&state).enrolar(auth.user_id, sellado, req.org_recovery_key_id).await?;
    Ok(Json(escrow_a_response(escrow)))
}

fn custodio_a_response(c: CustodioPendiente) -> CustodioPendienteResponse {
    CustodioPendienteResponse {
        user_id: c.user_id,
        email: c.email,
        display_name: c.display_name,
        public_key_x25519_b64: B64.encode(c.public_key_x25519),
    }
}

/// `GET /admin/account-recovery/custody` (QA-09).
pub async fn estado_custodia(State(state): State<AppState>, admin: AdminUser) -> Result<Json<EstadoCustodiaResponse>, ApiError> {
    let e = servicio(&state).estado_custodia(admin.user_id).await?;
    Ok(Json(EstadoCustodiaResponse {
        current: e.vigente.map(clave_a_response),
        my_envelope_b64: e.mi_sobre.map(|b| B64.encode(b)),
        pending_custodians: e.pendientes.into_iter().map(custodio_a_response).collect(),
        org_admins: e.admins.into_iter().map(custodio_a_response).collect(),
        escrows_on_server_key: e.escrows_en_servidor,
    }))
}

/// `POST /admin/account-recovery/org-keys` (QA-09) — clave generada en el
/// navegador del admin, con la privada ya sellada para cada custodio.
pub async fn crear_clave_org(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(req): Json<CrearClaveOrgRequest>,
) -> Result<Json<CrearClaveOrgResponse>, ApiError> {
    let publica = decodificar_b64("public_key_x25519_b64", &req.public_key_x25519_b64)?;
    let mut sobres = Vec::with_capacity(req.envelopes.len());
    for s in req.envelopes {
        sobres.push((s.admin_id, decodificar_b64("sealed_private_key_b64", &s.sealed_private_key_b64)?));
    }
    let id = servicio(&state).crear_clave_de_cliente(admin.user_id, publica, sobres).await?;
    Ok(Json(CrearClaveOrgResponse { id }))
}

/// `POST /admin/account-recovery/org-keys/{id}/envelopes` (QA-09).
pub async fn agregar_custodio(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<i32>,
    Json(req): Json<AgregarCustodioRequest>,
) -> Result<axum::http::StatusCode, ApiError> {
    let sellado = decodificar_b64("sealed_private_key_b64", &req.sealed_private_key_b64)?;
    servicio(&state).agregar_custodio(admin.user_id, id, req.admin_id, sellado).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// `DELETE /admin/account-recovery/server-key` (QA-09).
pub async fn purgar_clave_servidor(State(state): State<AppState>, admin: AdminUser) -> Result<Json<PurgaResponse>, ApiError> {
    let borrados = servicio(&state).purgar_clave_servidor(admin.user_id).await?;
    Ok(Json(PurgaResponse { escrows_deleted: borrados }))
}

/// `GET /admin/account-recovery/requests/{id}/custody-material` (QA-09).
pub async fn material_para_custodio(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<Uuid>,
) -> Result<Json<MaterialCustodioResponse>, ApiError> {
    let m = servicio(&state).material_para_custodio(admin.user_id, id).await?;
    Ok(Json(MaterialCustodioResponse {
        sealed_private_key_for_org_b64: B64.encode(m.sealed_private_key_for_org),
        requester_public_key_x25519_b64: B64.encode(m.requester_public_key_x25519),
        org_recovery_key_id: m.org_recovery_key_id,
        envelope_b64: B64.encode(m.sobre),
    }))
}

/// `POST /admin/account-recovery/requests/{id}/execute` (QA-09).
pub async fn ejecutar(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<Uuid>,
    Json(req): Json<EjecutarRequest>,
) -> Result<Json<SolicitudResponse>, ApiError> {
    let sellado = decodificar_b64("sealed_private_key_for_requester_b64", &req.sealed_private_key_for_requester_b64)?;
    let solicitud = servicio(&state).ejecutar(admin.user_id, id, sellado).await?;
    Ok(Json(solicitud_a_response(solicitud)))
}

/// Header con el token del solicitante (QA-10). Header y no query string:
/// las URLs terminan en logs de proxies.
const HEADER_TOKEN: &str = "x-ellkan-recovery-token";

/// `POST /account-recovery/requests` — sin sesión, a propósito (ver
/// `AccountRecoveryService::crear_solicitud`). Siempre la misma forma de
/// respuesta: la solicitud queda `unconfirmed` hasta que se confirma el
/// código enviado al email de la cuenta.
pub async fn crear_solicitud(
    State(state): State<AppState>,
    Json(req): Json<CrearSolicitudRequest>,
) -> Result<Json<SolicitudResponse>, ApiError> {
    let clave = decodificar_b64("requester_public_key_x25519_b64", &req.requester_public_key_x25519_b64)?;
    let id = servicio(&state).crear_solicitud(&req.email, clave).await?;
    Ok(Json(SolicitudResponse {
        id,
        status: "unconfirmed".to_string(),
        approvals_count: 0,
        sealed_private_key_for_requester_b64: None,
    }))
}

/// `POST /account-recovery/requests/{id}/confirm` — QA-10, ver
/// `AccountRecoveryService::confirmar_solicitud`.
pub async fn confirmar_solicitud(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(req): Json<ConfirmarSolicitudRequest>,
) -> Result<Json<ConfirmarSolicitudResponse>, ApiError> {
    let token = servicio(&state).confirmar_solicitud(id, &req.code).await?;
    Ok(Json(ConfirmarSolicitudResponse { requester_token_b64: B64.encode(token) }))
}

/// `GET /account-recovery/requests/{id}` — poll sin sesión, con el token del
/// solicitante en `X-Ellkan-Recovery-Token`: conocer el id no alcanza.
pub async fn estado_solicitud(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<SolicitudResponse>, ApiError> {
    let token = headers
        .get(HEADER_TOKEN)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| B64.decode(v).ok())
        .ok_or(DomainError::NotFound)?;
    let solicitud = servicio(&state).estado_solicitud(id, &token).await?;
    Ok(Json(solicitud_a_response(solicitud)))
}

/// `POST /admin/account-recovery/requests/{id}/approve` — 2026-08-11:
/// extractor pasa de `AdminUser` a `AuthenticatedUser` porque la
/// autorización real (admin de organización O admin del grupo del
/// solicitante) ya no es una propiedad estática de la sesión, depende de
/// `id` — el gate vive en `AccountRecoveryService::autorizar_gestion`.
pub async fn aprobar(
    State(state): State<AppState>,
    actor: AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Result<Json<SolicitudResponse>, ApiError> {
    let solicitud = servicio(&state).aprobar(actor.user_id, id).await?;
    Ok(Json(solicitud_a_response(solicitud)))
}

/// `POST /admin/account-recovery/requests/{id}/reject` — 2026-08-11, mismo
/// criterio de extractor/autorización que `aprobar`.
pub async fn rechazar(
    State(state): State<AppState>,
    actor: AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Result<Json<SolicitudResponse>, ApiError> {
    let solicitud = servicio(&state).rechazar(actor.user_id, id).await?;
    Ok(Json(solicitud_a_response(solicitud)))
}

pub async fn completar(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(req): Json<CompletarSolicitudRequest>,
) -> Result<(), ApiError> {
    let token = decodificar_b64("requester_token_b64", &req.requester_token_b64)?;
    let blob = decodificar_b64("encrypted_private_key_blob_b64", &req.encrypted_private_key_blob_b64)?;
    let nonce = decodificar_b64("private_key_nonce_b64", &req.private_key_nonce_b64)?;
    let salt = decodificar_b64("kdf_salt_b64", &req.kdf_salt_b64)?;
    let auth_key = crate::validacion::sello_nuevo(&req.kdf_params, &req.auth_key_b64)?;
    let nueva = NuevaClavePrivada {
        encrypted_private_key_blob: blob,
        private_key_nonce: nonce,
        kdf_salt: salt,
        kdf_params: req.kdf_params,
        auth_key,
    };
    let prueba = PruebaDePosesion {
        challenge: decodificar_b64("challenge_nonce_b64", &req.challenge_nonce_b64)?,
        firma: decodificar_b64("signature_b64", &req.signature_b64)?,
    };

    servicio(&state).completar(id, &token, nueva, &prueba).await?;
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
/// ver `AccountRecoveryService::listar_pendientes`. 2026-08-11: extractor
/// `AuthenticatedUser` (no `AdminUser`) — un admin de grupo también puede
/// llamar esto, el filtro de visibilidad vive en el Service.
pub async fn listar_solicitudes_pendientes(
    State(state): State<AppState>,
    actor: AuthenticatedUser,
) -> Result<Json<Vec<SolicitudAdminResponse>>, ApiError> {
    let solicitudes = servicio(&state).listar_pendientes(actor.user_id).await?;
    Ok(Json(solicitudes.into_iter().map(solicitud_admin_a_response).collect()))
}
