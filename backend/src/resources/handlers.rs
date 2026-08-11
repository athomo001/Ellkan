// Autor: Athan Espinoza

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::Json;
use uuid::Uuid;

use crate::auth::extractor::AuthenticatedUser;
use crate::b64;
use crate::error::{ApiError, DomainError};
use crate::folders::repository::FolderItemRepository;
use crate::folders::service::FolderService;
use crate::state::AppState;
use crate::tags::service::TagService;

use super::dto::{
    ActualizarRecursoRequest, CambiarNivelRequest, CompartirLoteItemResultado, CompartirLoteRequest,
    CompartirLoteResponse, CompartirRequest, CrearRecursoRequest, DestinatarioResponse, ListarQuery,
    MoverRecursoRequest, PermisoGranteeResponse, RecursoResponse, RekeyMetadataRequest, SecretoResponse, TotpResponse,
};
use super::models::{EnvelopeInput, NivelPermiso};
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

fn a_response(recurso: super::models::Resource, resource_type_slug: String) -> RecursoResponse {
    RecursoResponse {
        id: recurso.id,
        resource_type_id: recurso.resource_type_id,
        resource_type_slug,
        metadata_ciphertext_b64: b64::encode(&recurso.metadata_ciphertext),
        metadata_nonce_b64: b64::encode(&recurso.metadata_nonce),
        created_by: recurso.created_by,
        created_at: recurso.created_at,
        updated_at: recurso.updated_at,
        metadata_key_type: recurso.metadata_key_type,
        metadata_key_id: recurso.metadata_key_id,
        folder_id: None,
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

    Ok(Json(a_response(recurso, req.resource_type_slug)))
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

    // F-11: siempre se calcula (no sólo cuando `folder_id` filtra) — la UI
    // necesita saber en qué carpeta está cada recurso para mostrarlo/mover
    // sin una consulta aparte por fila.
    let posiciones = state.items_de_carpeta.posiciones_de_recursos(auth.user_id).await.map_err(DomainError::from)?;
    let slugs = state.tipos_recurso.mapa_id_a_slug().await.map_err(DomainError::from)?;

    let recursos: Vec<RecursoResponse> = recursos
        .into_iter()
        .map(|r| {
            let slug = slugs.get(&r.resource_type_id).cloned().unwrap_or_default();
            let mut resp = a_response(r, slug);
            resp.folder_id = posiciones.get(&resp.id).copied();
            resp
        })
        .collect();

    let recursos = match q.folder_id {
        None => recursos,
        Some(folder_id) => recursos.into_iter().filter(|r| r.folder_id == Some(folder_id)).collect(),
    };

    Ok(Json(recursos))
}

pub async fn obtener(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path(resource_id): Path<Uuid>,
) -> Result<Json<RecursoResponse>, ApiError> {
    let recurso = servicio(&state).obtener(resource_id, auth.user_id).await?;
    let slug = state
        .tipos_recurso
        .mapa_id_a_slug()
        .await
        .map_err(DomainError::from)?
        .get(&recurso.resource_type_id)
        .cloned()
        .unwrap_or_default();
    Ok(Json(a_response(recurso, slug)))
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

fn nivel_de(level: Option<&str>) -> Result<NivelPermiso, DomainError> {
    match level {
        None | Some("read") => Ok(NivelPermiso::Read),
        Some("update") => Ok(NivelPermiso::Update),
        Some("owner") => Ok(NivelPermiso::Owner),
        Some(_) => Err(DomainError::ValidacionInvalida("level inválido".into())),
    }
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
    let nivel = nivel_de(req.level.as_deref())?;

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

/// `POST /resources/share-bulk` (módulo 3) — el cliente ya resolvió N×M
/// sellados client-side (uno por par recurso×destinatario); acá sólo se
/// aplican en loop. Un ítem con `level`/base64 inválido, o que el caller no
/// pueda compartir, queda registrado en `resultados` con su propio error
/// — nunca aborta el resto del lote.
pub async fn compartir_lote(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Json(req): Json<CompartirLoteRequest>,
) -> Result<Json<CompartirLoteResponse>, ApiError> {
    let mut validos = Vec::with_capacity(req.items.len());
    let mut resultados = Vec::new();

    for item in req.items {
        let decodificado = (|| -> Result<_, DomainError> {
            let sealed_dek = b64::decode(&item.sealed_dek_b64)
                .map_err(|_| DomainError::ValidacionInvalida("sealed_dek_b64 inválido".into()))?;
            let secret_ciphertext = b64::decode(&item.secret_ciphertext_b64)
                .map_err(|_| DomainError::ValidacionInvalida("secret_ciphertext_b64 inválido".into()))?;
            let secret_nonce = b64::decode(&item.secret_nonce_b64)
                .map_err(|_| DomainError::ValidacionInvalida("secret_nonce_b64 inválido".into()))?;
            let nivel = nivel_de(item.level.as_deref())?;
            Ok((sealed_dek, secret_ciphertext, secret_nonce, nivel))
        })();

        match decodificado {
            Ok((sealed_dek, secret_ciphertext, secret_nonce, nivel)) => {
                validos.push(super::service::ItemCompartirLote {
                    resource_id: item.resource_id,
                    recipient_id: item.recipient_user_id,
                    sealed_dek,
                    secret_ciphertext,
                    secret_nonce,
                    nivel,
                });
            }
            Err(e) => resultados.push(CompartirLoteItemResultado {
                resource_id: item.resource_id,
                recipient_user_id: item.recipient_user_id,
                error: Some(e.to_string()),
            }),
        }
    }

    let aplicados = servicio(&state).compartir_lote(auth.user_id, validos).await;
    resultados.extend(aplicados.into_iter().map(|(resource_id, recipient_user_id, error)| {
        CompartirLoteItemResultado { resource_id, recipient_user_id, error }
    }));

    Ok(Json(CompartirLoteResponse { resultados }))
}

/// `GET /resources/{id}/permissions` — quién tiene acceso y en qué nivel.
pub async fn listar_permisos(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path(resource_id): Path<Uuid>,
) -> Result<Json<Vec<PermisoGranteeResponse>>, ApiError> {
    let grantees = servicio(&state).listar_permisos(resource_id, auth.user_id).await?;
    Ok(Json(
        grantees
            .into_iter()
            .map(|g| PermisoGranteeResponse { grantee_type: g.grantee_type, grantee_id: g.grantee_id, level: g.level, label: g.label })
            .collect(),
    ))
}

/// `PUT /resources/{id}/permissions/{grantee_type}/{grantee_id}` — sólo
/// cambia el nivel, no toca ninguna crypto.
pub async fn cambiar_nivel_permiso(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path((resource_id, grantee_type, grantee_id)): Path<(Uuid, String, Uuid)>,
    Json(req): Json<CambiarNivelRequest>,
) -> Result<(), ApiError> {
    let nivel = match req.level.as_str() {
        "read" => NivelPermiso::Read,
        "update" => NivelPermiso::Update,
        "owner" => NivelPermiso::Owner,
        _ => return Err(DomainError::ValidacionInvalida("level inválido".into()).into()),
    };
    servicio(&state).cambiar_nivel(resource_id, auth.user_id, &grantee_type, grantee_id, nivel).await?;
    Ok(())
}

/// `DELETE /resources/{id}/permissions/{grantee_type}/{grantee_id}` — revoca acceso.
pub async fn revocar_permiso(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path((resource_id, grantee_type, grantee_id)): Path<(Uuid, String, Uuid)>,
) -> Result<(), ApiError> {
    servicio(&state).revocar_permiso(resource_id, auth.user_id, &grantee_type, grantee_id).await?;
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

/// `GET /resources/{id}/recipients` (F-07).
pub async fn recipients(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path(resource_id): Path<Uuid>,
) -> Result<Json<Vec<DestinatarioResponse>>, ApiError> {
    let destinatarios = servicio(&state).listar_destinatarios(resource_id, auth.user_id).await?;
    Ok(Json(
        destinatarios
            .into_iter()
            .map(|d| DestinatarioResponse { user_id: d.user_id, public_key_x25519_b64: b64::encode(&d.public_key_x25519) })
            .collect(),
    ))
}

/// `PUT /resources/{id}` (F-07) — concurrencia optimista real vía
/// `If-Match`, no un detalle cosmético: sin header, o con un valor que no
/// coincide con el `updated_at` actual, se rechaza antes de tocar nada.
pub async fn actualizar(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path(resource_id): Path<Uuid>,
    headers: HeaderMap,
    Json(req): Json<ActualizarRecursoRequest>,
) -> Result<Json<RecursoResponse>, ApiError> {
    let if_match = headers
        .get("if-match")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| DomainError::ValidacionInvalida("falta el header If-Match".into()))?;
    let expected_updated_at = time::OffsetDateTime::parse(if_match, &time::format_description::well_known::Rfc3339)
        .map_err(|_| DomainError::ValidacionInvalida("If-Match debe ser una fecha RFC3339 válida".into()))?;

    let metadata_ciphertext = b64::decode(&req.metadata_ciphertext_b64)
        .map_err(|_| DomainError::ValidacionInvalida("metadata_ciphertext_b64 inválido".into()))?;
    let metadata_nonce = b64::decode(&req.metadata_nonce_b64)
        .map_err(|_| DomainError::ValidacionInvalida("metadata_nonce_b64 inválido".into()))?;

    let mut envelopes = Vec::with_capacity(req.envelopes.len());
    for e in req.envelopes {
        envelopes.push(EnvelopeInput {
            user_id: e.recipient_user_id,
            sealed_dek: b64::decode(&e.sealed_dek_b64)
                .map_err(|_| DomainError::ValidacionInvalida("sealed_dek_b64 inválido".into()))?,
            secret_ciphertext: b64::decode(&e.secret_ciphertext_b64)
                .map_err(|_| DomainError::ValidacionInvalida("secret_ciphertext_b64 inválido".into()))?,
            secret_nonce: b64::decode(&e.secret_nonce_b64)
                .map_err(|_| DomainError::ValidacionInvalida("secret_nonce_b64 inválido".into()))?,
        });
    }

    let recurso = servicio(&state)
        .editar(resource_id, auth.user_id, expected_updated_at, &metadata_ciphertext, &metadata_nonce, envelopes)
        .await?;
    let slug = state
        .tipos_recurso
        .mapa_id_a_slug()
        .await
        .map_err(DomainError::from)?
        .get(&recurso.resource_type_id)
        .cloned()
        .unwrap_or_default();

    Ok(Json(a_response(recurso, slug)))
}

/// `PUT /resources/{id}/move` (F-11) — la lógica vive en `FolderService`
/// (misma que mueve carpetas y comparte, ver `folders/service.rs`), este
/// handler sólo la construye con los repos de `AppState`.
pub async fn mover(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path(resource_id): Path<Uuid>,
    Json(req): Json<MoverRecursoRequest>,
) -> Result<(), ApiError> {
    FolderService { carpetas: &state.carpetas, items: &state.items_de_carpeta, permisos: &state.permisos }
        .mover_recurso(auth.user_id, resource_id, req.folder_id)
        .await?;
    Ok(())
}
