// Autor: Athan Espinoza

use axum::extract::{Path, State};
use axum::Json;
use uuid::Uuid;

use crate::auth::extractor::{AdminUser, AuthenticatedUser};
use crate::b64;
use crate::error::{ApiError, DomainError};
use crate::state::AppState;

use super::dto::{
    ActualizarExternalSharePolicyRequest, CrearExternalShareRequest, ExternalShareContenidoResponse,
    ExternalShareCreadoResponse, ExternalSharePolicyResponse,
};
use super::repository::{PgExternalSharePolicyRepository, PgExternalShareRepository};
use super::service::ExternalShareService;

type Servicio<'a> = ExternalShareService<'a, PgExternalShareRepository, PgExternalSharePolicyRepository>;

fn servicio(state: &AppState) -> Servicio<'_> {
    ExternalShareService {
        shares: &state.external_shares,
        policy: &state.external_share_policy,
        eventos: state.eventos.clone(),
    }
}

pub async fn crear(
    State(state): State<AppState>,
    usuario: AuthenticatedUser,
    Json(req): Json<CrearExternalShareRequest>,
) -> Result<Json<ExternalShareCreadoResponse>, ApiError> {
    let ciphertext = b64::decode(&req.ciphertext_b64)
        .map_err(|_| DomainError::ValidacionInvalida("ciphertext_b64 inválido".into()))?;
    let password_salt = req
        .password_salt_b64
        .as_deref()
        .map(b64::decode)
        .transpose()
        .map_err(|_| DomainError::ValidacionInvalida("password_salt_b64 inválido".into()))?;

    let fila = servicio(&state)
        .crear(usuario.user_id, ciphertext, req.password_protected, password_salt, req.max_views, req.expires_in_hours)
        .await?;

    Ok(Json(ExternalShareCreadoResponse { id: fila.id, max_views: fila.max_views, expires_at: fila.expires_at }))
}

pub async fn revocar(
    State(state): State<AppState>,
    usuario: AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Result<(), ApiError> {
    servicio(&state).revocar(usuario.user_id, id).await?;
    Ok(())
}

/// **Sin extractor de sesión, a propósito** — el único endpoint de toda la
/// API que no exige auth (F-26): lo abre el destinatario externo, que no
/// tiene cuenta. La barrera es el `id` de alta entropía + el rate limiting
/// dedicado (`lib.rs`), no una sesión.
pub async fn obtener(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ExternalShareContenidoResponse>, ApiError> {
    let contenido = servicio(&state).acceder(id).await?;
    Ok(Json(ExternalShareContenidoResponse {
        ciphertext_b64: b64::encode(&contenido.ciphertext),
        password_protected: contenido.password_protected,
        password_salt_b64: contenido.password_salt.as_deref().map(b64::encode),
    }))
}

pub async fn politica(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<ExternalSharePolicyResponse>, ApiError> {
    let p = servicio(&state).politica().await?;
    Ok(Json(ExternalSharePolicyResponse {
        enabled: p.enabled,
        max_expiration_hours: p.max_expiration_hours,
        require_password: p.require_password,
    }))
}

pub async fn actualizar_politica(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(req): Json<ActualizarExternalSharePolicyRequest>,
) -> Result<Json<ExternalSharePolicyResponse>, ApiError> {
    let p = servicio(&state)
        .actualizar_politica(admin.user_id, req.enabled, req.max_expiration_hours, req.require_password)
        .await?;
    Ok(Json(ExternalSharePolicyResponse {
        enabled: p.enabled,
        max_expiration_hours: p.max_expiration_hours,
        require_password: p.require_password,
    }))
}
