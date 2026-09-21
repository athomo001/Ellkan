// Autor: Athan Espinoza

//! `GET /sync?since=<cursor>` (F-47) — un solo endpoint de agregación,
//! sin capa de Service propia: no hay ninguna regla de negocio nueva acá,
//! sólo consultas de "qué cambió" contra repos que ya existen (mismo
//! criterio que `system_status::handlers`, que tampoco tiene Service).
//!
//! **Gap conocido, aceptado en esta primera versión**: no cubre
//! `resource_tags` (aplicar/quitar un tag de un recurso no toca ningún
//! timestamp hoy — ni `resources.updated_at` ni nada en `resource_tags`
//! en sí). Un cliente que sólo aplicó/quitó tags desde el último sync no
//! se entera hasta el próximo cambio real de ese recurso, o un sync
//! completo (`since` ausente). No es pérdida de datos — la asociación
//! sigue viva en el servidor — sólo un retraso de propagación. Iterar acá
//! si aparece necesidad real, mismo criterio que spec/13 §7 ya documenta
//! para el merge de conflictos ("primera versión: sólo este caso").

use std::collections::{HashMap, HashSet};

use axum::extract::{Query, State};
use axum::Json;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::auth::extractor::AuthenticatedUser;
use crate::b64;
use crate::error::{ApiError, DomainError};
use crate::folders::repository::{FolderItemRepository, FolderRepository};
use crate::resources::repository::{ResourceRepository, ResourceTypeRepository, SecretEnvelopeRepository};
use crate::state::AppState;
use crate::tags::repository::TagRepository;

use super::dto::{SyncFolderItem, SyncQuery, SyncResourceItem, SyncResponse, SyncSecretItem, SyncTagItem};

fn secreto_a_item(e: crate::resources::models::SecretEnvelope) -> SyncSecretItem {
    SyncSecretItem {
        sealed_dek_b64: b64::encode(&e.sealed_dek),
        secret_ciphertext_b64: b64::encode(&e.secret_ciphertext),
        secret_nonce_b64: b64::encode(&e.secret_nonce),
    }
}

#[allow(clippy::too_many_arguments)]
async fn recurso_a_item(
    state: &AppState,
    user_id: Uuid,
    recurso: crate::resources::models::Resource,
    slugs: &HashMap<Uuid, String>,
    posiciones_actuales: &HashMap<Uuid, Uuid>,
) -> Result<SyncResourceItem, ApiError> {
    let envelope = state.envolturas.buscar(recurso.id, user_id).await.map_err(DomainError::from)?;
    Ok(SyncResourceItem {
        id: recurso.id,
        deleted: false,
        resource_type_slug: slugs.get(&recurso.resource_type_id).cloned(),
        metadata_ciphertext_b64: Some(b64::encode(&recurso.metadata_ciphertext)),
        metadata_nonce_b64: Some(b64::encode(&recurso.metadata_nonce)),
        created_by: recurso.created_by,
        created_at: Some(recurso.created_at),
        updated_at: Some(recurso.updated_at),
        metadata_key_type: Some(recurso.metadata_key_type),
        metadata_key_id: recurso.metadata_key_id,
        folder_id: posiciones_actuales.get(&recurso.id).copied(),
        secret: envelope.map(secreto_a_item),
    })
}

pub async fn sync(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Query(q): Query<SyncQuery>,
) -> Result<Json<SyncResponse>, ApiError> {
    let user_id = auth.user_id;
    let desde = q.since.unwrap_or(OffsetDateTime::UNIX_EPOCH);
    // Fijado ANTES de consultar (no el máximo `updated_at` que se termine
    // viendo): un cambio que llegue a mitad de esta función nunca se
    // pierde — en el peor caso vuelve a aparecer en el próximo pull.
    let cursor = OffsetDateTime::now_utc();

    // --- resources: unión de "contenido cambió" + "posición cambió" ---
    let slugs = state.tipos_recurso.mapa_id_a_slug().await.map_err(DomainError::from)?;
    let posiciones_actuales = state.items_de_carpeta.posiciones_de_recursos(user_id).await.map_err(DomainError::from)?;
    let posiciones_cambiadas = state.items_de_carpeta.posiciones_de_recursos_cambiadas_desde(user_id, desde).await.map_err(DomainError::from)?;
    let eliminados_ids: HashSet<Uuid> = state.recursos.ids_eliminados_desde(user_id, desde).await.map_err(DomainError::from)?.into_iter().collect();

    let mut ids_vistos: HashSet<Uuid> = HashSet::new();
    let mut resources = Vec::new();

    for recurso in state.recursos.cambios_desde(user_id, desde).await.map_err(DomainError::from)? {
        ids_vistos.insert(recurso.id);
        resources.push(recurso_a_item(&state, user_id, recurso, &slugs, &posiciones_actuales).await?);
    }

    for resource_id in posiciones_cambiadas.keys() {
        if ids_vistos.contains(resource_id) || eliminados_ids.contains(resource_id) {
            continue;
        }
        if let Some(recurso) = state.recursos.buscar(*resource_id).await.map_err(DomainError::from)? {
            ids_vistos.insert(recurso.id);
            resources.push(recurso_a_item(&state, user_id, recurso, &slugs, &posiciones_actuales).await?);
        }
    }

    for id in eliminados_ids {
        resources.push(SyncResourceItem {
            id,
            deleted: true,
            resource_type_slug: None,
            metadata_ciphertext_b64: None,
            metadata_nonce_b64: None,
            created_by: None,
            created_at: None,
            updated_at: None,
            metadata_key_type: None,
            metadata_key_id: None,
            folder_id: None,
            secret: None,
        });
    }

    // --- folders ---
    let mut folders = Vec::new();
    for n in state.items_de_carpeta.cambios_desde(user_id, desde).await.map_err(DomainError::from)? {
        folders.push(SyncFolderItem {
            folder_id: n.folder_id,
            deleted: false,
            parent_folder_id: n.parent_folder_id,
            name_ciphertext_b64: Some(b64::encode(&n.name_ciphertext)),
            name_nonce_b64: Some(b64::encode(&n.name_nonce)),
        });
    }
    for id in state.carpetas.ids_eliminadas_desde(desde).await.map_err(DomainError::from)? {
        folders.push(SyncFolderItem { folder_id: id, deleted: true, parent_folder_id: None, name_ciphertext_b64: None, name_nonce_b64: None });
    }

    // --- tags ---
    let mut tags = Vec::new();
    for t in state.tags.cambios_desde(user_id, desde).await.map_err(DomainError::from)? {
        tags.push(SyncTagItem { id: t.id, deleted: false, name: Some(t.name), is_shared: Some(t.is_shared), created_by: t.created_by });
    }
    for id in state.tags.ids_eliminados_desde(user_id, desde).await.map_err(DomainError::from)? {
        tags.push(SyncTagItem { id, deleted: true, name: None, is_shared: None, created_by: None });
    }

    Ok(Json(SyncResponse { cursor, resources, folders, tags }))
}
