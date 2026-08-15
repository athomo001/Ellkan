// Autor: Athan Espinoza

use axum::extract::{Path, State};
use axum::Json;
use uuid::Uuid;

use crate::auth::extractor::{AdminUser, AuthenticatedUser};
use crate::b64;
use crate::error::{ApiError, DomainError};
use crate::state::AppState;

use super::dto::{
    ActualizarShareExemptRequest, AgregarMiembroRequest, CrearGrupoRequest, GrupoResponse, MiembroResponse,
    MoverGrupoRequest, SetManagerRequest,
};
use super::models::{EnvelopeParaMiembroNuevo, Group, Miembro};
use super::service::GroupService;

type Servicio<'a> = GroupService<
    'a,
    super::repository::PgGroupRepository,
    super::repository::PgGroupMemberRepository,
    super::repository::PgOrganizationRepository,
    crate::resources::repository::PgPermissionRepository,
    crate::admin::repository::PgRoleRepository,
>;

fn servicio(state: &AppState) -> Servicio<'_> {
    GroupService {
        grupos: &state.grupos,
        miembros: &state.miembros_de_grupo,
        organizacion: &state.organizacion,
        permisos: &state.permisos,
        roles: &state.roles,
        eventos: state.eventos.clone(),
    }
}

fn a_response(grupo: Group) -> GrupoResponse {
    GrupoResponse {
        id: grupo.id,
        name: grupo.name,
        parent_group_id: grupo.parent_group_id,
        share_exempt: grupo.share_exempt,
        members: vec![],
    }
}

fn miembro_a_response(m: Miembro) -> MiembroResponse {
    MiembroResponse { user_id: m.user_id, is_admin: m.is_admin, email: m.email, display_name: m.display_name }
}

/// `GET /groups/{id}/resources` (F-12).
pub async fn recursos_compartidos(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path(group_id): Path<Uuid>,
) -> Result<Json<Vec<Uuid>>, ApiError> {
    let ids = servicio(&state).recursos_compartidos(auth.user_id, group_id).await?;
    Ok(Json(ids))
}

pub async fn listar(
    State(state): State<AppState>,
    _auth: AuthenticatedUser,
) -> Result<Json<Vec<GrupoResponse>>, ApiError> {
    let raices = servicio(&state).listar_raices().await?;
    Ok(Json(raices.into_iter().map(a_response).collect()))
}

pub async fn crear(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Json(req): Json<CrearGrupoRequest>,
) -> Result<Json<GrupoResponse>, ApiError> {
    let grupo = servicio(&state).crear(auth.user_id, req.id, &req.name, req.parent_group_id).await?;
    Ok(Json(a_response(grupo)))
}

pub async fn obtener(
    State(state): State<AppState>,
    _auth: AuthenticatedUser,
    Path(group_id): Path<Uuid>,
) -> Result<Json<GrupoResponse>, ApiError> {
    let servicio = servicio(&state);
    let grupo = servicio.obtener(group_id).await?;
    let miembros = servicio.miembros(group_id).await?;
    let mut respuesta = a_response(grupo);
    respuesta.members = miembros.into_iter().map(miembro_a_response).collect();
    Ok(Json(respuesta))
}

pub async fn subgrupos(
    State(state): State<AppState>,
    _auth: AuthenticatedUser,
    Path(group_id): Path<Uuid>,
) -> Result<Json<Vec<GrupoResponse>>, ApiError> {
    let hijos = servicio(&state).subgrupos(group_id).await?;
    Ok(Json(hijos.into_iter().map(a_response).collect()))
}

pub async fn mover(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path(group_id): Path<Uuid>,
    Json(req): Json<MoverGrupoRequest>,
) -> Result<(), ApiError> {
    servicio(&state).mover(auth.user_id, group_id, req.new_parent_group_id).await?;
    Ok(())
}

pub async fn agregar_miembro(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path((group_id, user_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<AgregarMiembroRequest>,
) -> Result<(), ApiError> {
    let mut envelopes = Vec::with_capacity(req.envelopes.len());
    for e in req.envelopes {
        let sealed_dek = b64::decode(&e.sealed_dek_b64)
            .map_err(|_| DomainError::ValidacionInvalida("sealed_dek_b64 inválido".into()))?;
        let secret_ciphertext = b64::decode(&e.secret_ciphertext_b64)
            .map_err(|_| DomainError::ValidacionInvalida("secret_ciphertext_b64 inválido".into()))?;
        let secret_nonce = b64::decode(&e.secret_nonce_b64)
            .map_err(|_| DomainError::ValidacionInvalida("secret_nonce_b64 inválido".into()))?;
        envelopes.push(EnvelopeParaMiembroNuevo {
            resource_id: e.resource_id,
            sealed_dek,
            secret_ciphertext,
            secret_nonce,
        });
    }

    servicio(&state)
        .agregar_miembro(auth.user_id, group_id, user_id, req.is_admin, envelopes)
        .await?;
    Ok(())
}

pub async fn quitar_miembro(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path((group_id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<(), ApiError> {
    servicio(&state).quitar_miembro(auth.user_id, group_id, user_id).await?;
    Ok(())
}

pub async fn set_manager(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path((group_id, user_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<SetManagerRequest>,
) -> Result<(), ApiError> {
    servicio(&state).set_manager(auth.user_id, group_id, user_id, req.is_admin).await?;
    Ok(())
}

pub async fn eliminar(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
    Path(group_id): Path<Uuid>,
) -> Result<(), ApiError> {
    servicio(&state).eliminar(auth.user_id, group_id).await?;
    Ok(())
}

/// `PUT /groups/{id}/share-exempt` — `AdminUser`, no `AuthenticatedUser`:
/// a propósito exige admin de organización, no admin del grupo puntual
/// (ver comentario de `GroupService::actualizar_share_exempt`).
pub async fn actualizar_share_exempt(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(group_id): Path<Uuid>,
    Json(req): Json<ActualizarShareExemptRequest>,
) -> Result<Json<GrupoResponse>, ApiError> {
    let grupo = servicio(&state).actualizar_share_exempt(admin.user_id, group_id, req.exempt).await?;
    Ok(Json(a_response(grupo)))
}
