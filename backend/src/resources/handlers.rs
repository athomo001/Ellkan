// Autor: Athan Espinoza

use axum::extract::{Path, State};
use axum::Json;
use uuid::Uuid;

use crate::auth::extractor::AuthenticatedUser;
use crate::b64;
use crate::error::{ApiError, DomainError};
use crate::state::AppState;

use super::dto::{CompartirRequest, CrearRecursoRequest, RecursoResponse, SecretoResponse};
use super::models::NivelPermiso;
use super::repository::ResourceTypeRepository;
use super::service::ResourceService;

type Servicio<'a> = ResourceService<
    'a,
    super::repository::PgResourceRepository,
    super::repository::PgSecretEnvelopeRepository,
    super::repository::PgPermissionRepository,
>;

fn servicio(state: &AppState) -> Servicio<'_> {
    ResourceService {
        recursos: &state.recursos,
        envolturas: &state.envolturas,
        permisos: &state.permisos,
    }
}

fn a_response(recurso: super::models::Resource) -> RecursoResponse {
    RecursoResponse {
        id: recurso.id,
        resource_type_id: recurso.resource_type_id,
        metadata_ciphertext_b64: b64::encode(&recurso.metadata_ciphertext),
        metadata_nonce_b64: b64::encode(&recurso.metadata_nonce),
        created_by: recurso.created_by,
        created_at: recurso.created_at,
    }
}

pub async fn crear(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Json(req): Json<CrearRecursoRequest>,
) -> Result<Json<RecursoResponse>, ApiError> {
    let resource_type_id = state
        .tipos_recurso
        .id_por_slug(&req.resource_type_slug)
        .await
        .map_err(DomainError::from)?
        .ok_or_else(|| DomainError::ValidacionInvalida("resource_type_slug desconocido".into()))?;

    let metadata_ciphertext = b64::decode(&req.metadata_ciphertext_b64)
        .map_err(|_| DomainError::ValidacionInvalida("metadata_ciphertext_b64 inválido".into()))?;
    let metadata_nonce = b64::decode(&req.metadata_nonce_b64)
        .map_err(|_| DomainError::ValidacionInvalida("metadata_nonce_b64 inválido".into()))?;
    let sealed_dek = b64::decode(&req.sealed_dek_b64)
        .map_err(|_| DomainError::ValidacionInvalida("sealed_dek_b64 inválido".into()))?;
    let secret_ciphertext = b64::decode(&req.secret_ciphertext_b64)
        .map_err(|_| DomainError::ValidacionInvalida("secret_ciphertext_b64 inválido".into()))?;
    let secret_nonce = b64::decode(&req.secret_nonce_b64)
        .map_err(|_| DomainError::ValidacionInvalida("secret_nonce_b64 inválido".into()))?;

    let recurso = servicio(&state)
        .crear(
            req.id,
            resource_type_id,
            &metadata_ciphertext,
            &metadata_nonce,
            auth.user_id,
            &sealed_dek,
            &secret_ciphertext,
            &secret_nonce,
        )
        .await?;

    Ok(Json(a_response(recurso)))
}

pub async fn listar(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
) -> Result<Json<Vec<RecursoResponse>>, ApiError> {
    let recursos = servicio(&state).listar_visibles(auth.user_id).await?;
    Ok(Json(recursos.into_iter().map(a_response).collect()))
}

pub async fn obtener(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path(resource_id): Path<Uuid>,
) -> Result<Json<RecursoResponse>, ApiError> {
    let recurso = servicio(&state).obtener(resource_id, auth.user_id).await?;
    Ok(Json(a_response(recurso)))
}

pub async fn obtener_secreto(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path(resource_id): Path<Uuid>,
) -> Result<Json<SecretoResponse>, ApiError> {
    let envelope = servicio(&state).obtener_secreto(resource_id, auth.user_id).await?;
    Ok(Json(SecretoResponse {
        sealed_dek_b64: b64::encode(&envelope.sealed_dek),
        secret_ciphertext_b64: b64::encode(&envelope.secret_ciphertext),
        secret_nonce_b64: b64::encode(&envelope.secret_nonce),
    }))
}

pub async fn compartir(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path(resource_id): Path<Uuid>,
    Json(req): Json<CompartirRequest>,
) -> Result<(), ApiError> {
    let sealed_dek = b64::decode(&req.sealed_dek_b64)
        .map_err(|_| DomainError::ValidacionInvalida("sealed_dek_b64 inválido".into()))?;
    let secret_ciphertext = b64::decode(&req.secret_ciphertext_b64)
        .map_err(|_| DomainError::ValidacionInvalida("secret_ciphertext_b64 inválido".into()))?;
    let secret_nonce = b64::decode(&req.secret_nonce_b64)
        .map_err(|_| DomainError::ValidacionInvalida("secret_nonce_b64 inválido".into()))?;

    let nivel = match req.level.as_deref() {
        None | Some("read") => NivelPermiso::Read,
        Some("update") => NivelPermiso::Update,
        Some("owner") => NivelPermiso::Owner,
        Some(_) => return Err(DomainError::ValidacionInvalida("level inválido".into()).into()),
    };

    servicio(&state)
        .compartir(
            resource_id,
            auth.user_id,
            req.recipient_user_id,
            &sealed_dek,
            &secret_ciphertext,
            &secret_nonce,
            nivel,
        )
        .await?;

    Ok(())
}
