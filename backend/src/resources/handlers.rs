// Autor: Athan Espinoza

use axum::extract::{Path, Query, State};
use axum::Json;
use uuid::Uuid;

use crate::auth::extractor::AuthenticatedUser;
use crate::b64;
use crate::error::{ApiError, DomainError};
use crate::state::AppState;
use crate::tags::service::TagService;

use super::dto::{
    CompartirRequest, CrearRecursoRequest, ListarQuery, RecursoResponse, RekeyMetadataRequest,
    SecretoResponse, TotpResponse,
};
use super::models::NivelPermiso;
use super::repository::ResourceTypeRepository;
use super::service::ResourceService;

type Servicio<'a> = ResourceService<
    'a,
    super::repository::PgResourceRepository,
    super::repository::PgSecretEnvelopeRepository,
    super::repository::PgPermissionRepository,
    super::repository::PgResourceTypeRepository,
>;

fn servicio(state: &AppState) -> Servicio<'_> {
    ResourceService {
        recursos: &state.recursos,
        envolturas: &state.envolturas,
        permisos: &state.permisos,
        tipos_recurso: &state.tipos_recurso,
        eventos: state.eventos.clone(),
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
        metadata_key_type: recurso.metadata_key_type,
        metadata_key_id: recurso.metadata_key_id,
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

    // El servidor rechaza un blob de metadata cuya envoltura no corresponda
    // a una clave declarada activa (F-06, criterio de aceptación literal) —
    // se valida acá, antes de tocar la fila de `resources`.
    if let Some(metadata_key_id) = req.metadata_key_id {
        use crate::metadata::repository::MetadataKeyRepository;
        let clave = state
            .claves_metadata
            .buscar(metadata_key_id)
            .await
            .map_err(DomainError::from)?
            .ok_or_else(|| DomainError::ValidacionInvalida("metadata_key_id no existe".into()))?;
        if clave.expired_at.is_some() {
            return Err(DomainError::ValidacionInvalida("metadata_key_id no está activa".into()).into());
        }
    }

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
            req.metadata_key_id,
        )
        .await?;

    Ok(Json(a_response(recurso)))
}

pub async fn listar(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Query(q): Query<ListarQuery>,
) -> Result<Json<Vec<RecursoResponse>>, ApiError> {
    let recursos = servicio(&state).listar_visibles(auth.user_id).await?;

    let recursos = match q.tag_id {
        None => recursos,
        Some(tag_id) => {
            let ids_con_tag = TagService { tags: &state.tags, permisos: &state.permisos }
                .recursos_por_tag(auth.user_id, tag_id)
                .await?;
            let ids_con_tag: std::collections::HashSet<Uuid> = ids_con_tag.into_iter().collect();
            recursos.into_iter().filter(|r| ids_con_tag.contains(&r.id)).collect()
        }
    };

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

pub async fn totp(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path(resource_id): Path<Uuid>,
) -> Result<Json<TotpResponse>, ApiError> {
    let tiene_totp = servicio(&state).tiene_totp(resource_id, auth.user_id).await?;
    Ok(Json(TotpResponse { tiene_totp }))
}

pub async fn rekey_metadata(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path(resource_id): Path<Uuid>,
    Json(req): Json<RekeyMetadataRequest>,
) -> Result<(), ApiError> {
    let metadata_ciphertext = b64::decode(&req.metadata_ciphertext_b64)
        .map_err(|_| DomainError::ValidacionInvalida("metadata_ciphertext_b64 inválido".into()))?;
    let metadata_nonce = b64::decode(&req.metadata_nonce_b64)
        .map_err(|_| DomainError::ValidacionInvalida("metadata_nonce_b64 inválido".into()))?;

    servicio(&state)
        .rekey_metadata(
            resource_id,
            auth.user_id,
            req.expected_current_metadata_key_id,
            req.new_metadata_key_id,
            &metadata_ciphertext,
            &metadata_nonce,
        )
        .await?;

    Ok(())
}
