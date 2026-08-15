// Autor: Athan Espinoza

use axum::extract::{Path, State};
use axum::Json;
use uuid::Uuid;

use crate::auth::extractor::AuthenticatedUser;
use crate::b64;
use crate::error::{ApiError, DomainError};
use crate::state::AppState;

use super::dto::{CompartirCarpetaRequest, CrearCarpetaRequest, MoverCarpetaRequest, NodoArbolResponse};
use super::service::FolderService;

type Servicio<'a> = FolderService<
    'a,
    super::repository::PgFolderRepository,
    super::repository::PgFolderItemRepository,
    crate::resources::repository::PgPermissionRepository,
    crate::groups::repository::PgGroupMemberRepository,
    crate::admin::repository::PgRoleRepository,
>;

fn servicio(state: &AppState) -> Servicio<'_> {
    FolderService {
        carpetas: &state.carpetas,
        items: &state.items_de_carpeta,
        permisos: &state.permisos,
        grupos: &state.miembros_de_grupo,
        roles: &state.roles,
    }
}

pub async fn crear(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Json(req): Json<CrearCarpetaRequest>,
) -> Result<Json<NodoArbolResponse>, ApiError> {
    let name_ciphertext = b64::decode(&req.name_ciphertext_b64)
        .map_err(|_| DomainError::ValidacionInvalida("name_ciphertext_b64 inválido".into()))?;
    let name_nonce = b64::decode(&req.name_nonce_b64)
        .map_err(|_| DomainError::ValidacionInvalida("name_nonce_b64 inválido".into()))?;

    let carpeta = servicio(&state)
        .crear(auth.user_id, req.id, &name_ciphertext, &name_nonce, req.parent_folder_id)
        .await?;

    Ok(Json(NodoArbolResponse {
        folder_id: carpeta.id,
        parent_folder_id: req.parent_folder_id,
        name_ciphertext_b64: req.name_ciphertext_b64,
        name_nonce_b64: req.name_nonce_b64,
        group_id: None,
    }))
}

pub async fn listar(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
) -> Result<Json<Vec<NodoArbolResponse>>, ApiError> {
    use crate::resources::repository::PermissionRepository;

    let arbol = servicio(&state).listar_arbol(auth.user_id).await?;
    let mut respuesta = Vec::with_capacity(arbol.len());
    for n in arbol {
        let group_id = state.permisos.grupo_grantee_de("folder", n.folder_id).await.map_err(DomainError::from)?;
        respuesta.push(NodoArbolResponse {
            folder_id: n.folder_id,
            parent_folder_id: n.parent_folder_id,
            name_ciphertext_b64: b64::encode(&n.name_ciphertext),
            name_nonce_b64: b64::encode(&n.name_nonce),
            group_id,
        });
    }
    Ok(Json(respuesta))
}

pub async fn mover(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path(folder_id): Path<Uuid>,
    Json(req): Json<MoverCarpetaRequest>,
) -> Result<(), ApiError> {
    servicio(&state).mover(auth.user_id, folder_id, req.new_parent_folder_id).await?;
    Ok(())
}

/// `POST /folders/{id}/share` (F-11) — exige admin de grupo/organización +
/// `owner` sobre la carpeta (2026-08-11: la restricción de elegibilidad
/// vive en `FolderService::verificar_puede_compartir`). `grantee_type`:
/// `"user"` (el cliente ya reselló el nombre para ese destinatario) o
/// `"group"` (el cliente ya reselló el nombre para cada miembro actual,
/// `req.member_envelopes`).
pub async fn compartir(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path(folder_id): Path<Uuid>,
    Json(req): Json<CompartirCarpetaRequest>,
) -> Result<(), ApiError> {
    match req.grantee_type.as_str() {
        "group" => {
            let miembros = req
                .member_envelopes
                .iter()
                .map(|m| {
                    let ciphertext = b64::decode(&m.name_ciphertext_b64)
                        .map_err(|_| DomainError::ValidacionInvalida("name_ciphertext_b64 inválido".into()))?;
                    let nonce = b64::decode(&m.name_nonce_b64)
                        .map_err(|_| DomainError::ValidacionInvalida("name_nonce_b64 inválido".into()))?;
                    Ok((m.user_id, ciphertext, nonce))
                })
                .collect::<Result<Vec<_>, DomainError>>()?;

            servicio(&state).compartir_a_grupo(auth.user_id, folder_id, req.grantee_id, &req.level, &miembros).await?;
        }
        "user" => {
            let name_ciphertext_b64 = req
                .name_ciphertext_b64
                .as_deref()
                .ok_or_else(|| DomainError::ValidacionInvalida("falta name_ciphertext_b64".into()))?;
            let name_nonce_b64 = req
                .name_nonce_b64
                .as_deref()
                .ok_or_else(|| DomainError::ValidacionInvalida("falta name_nonce_b64".into()))?;
            let name_ciphertext = b64::decode(name_ciphertext_b64)
                .map_err(|_| DomainError::ValidacionInvalida("name_ciphertext_b64 inválido".into()))?;
            let name_nonce = b64::decode(name_nonce_b64)
                .map_err(|_| DomainError::ValidacionInvalida("name_nonce_b64 inválido".into()))?;

            servicio(&state)
                .compartir(auth.user_id, folder_id, req.grantee_id, &req.level, &name_ciphertext, &name_nonce)
                .await?;
        }
        _ => return Err(DomainError::ValidacionInvalida("grantee_type debe ser 'user' o 'group'".into()).into()),
    }
    Ok(())
}
