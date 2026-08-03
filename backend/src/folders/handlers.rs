// Autor: Athan Espinoza

use axum::extract::{Path, State};
use axum::Json;
use uuid::Uuid;

use crate::auth::extractor::AuthenticatedUser;
use crate::b64;
use crate::error::{ApiError, DomainError};
use crate::state::AppState;

use super::dto::{CrearCarpetaRequest, MoverCarpetaRequest, NodoArbolResponse};
use super::service::FolderService;

type Servicio<'a> =
    FolderService<'a, super::repository::PgFolderRepository, super::repository::PgFolderItemRepository>;

fn servicio(state: &AppState) -> Servicio<'_> {
    FolderService { carpetas: &state.carpetas, items: &state.items_de_carpeta }
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
        name_ciphertext_b64: b64::encode(&carpeta.name_ciphertext),
        name_nonce_b64: b64::encode(&carpeta.name_nonce),
    }))
}

pub async fn listar(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
) -> Result<Json<Vec<NodoArbolResponse>>, ApiError> {
    let arbol = servicio(&state).listar_arbol(auth.user_id).await?;
    Ok(Json(
        arbol
            .into_iter()
            .map(|n| NodoArbolResponse {
                folder_id: n.folder_id,
                parent_folder_id: n.parent_folder_id,
                name_ciphertext_b64: b64::encode(&n.name_ciphertext),
                name_nonce_b64: b64::encode(&n.name_nonce),
            })
            .collect(),
    ))
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
