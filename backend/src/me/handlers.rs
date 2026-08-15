// Autor: Athan Espinoza

use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
use axum::Json;

use crate::admin::repository::RoleRepository;
use crate::auth::extractor::{AuthenticatedUser, SesionValida};
use crate::b64;
use crate::error::{ApiError, DomainError};
use crate::state::AppState;

use super::dto::{
    ActualizarAvatarRequest, ActualizarPreferenciasRequest, CambiarPassphraseRequest, PerfilResponse,
    PreferenciasResponse,
};
use super::models::{Avatar, NuevaClavePrivada, Preferencias};
use super::repository::PgPreferenciasRepository;
use super::service::{AvatarService, CambiarPassphraseService, PerfilService, PreferenciasService};
use crate::password_policy::repository::PgPasswordPolicyRepository;

type Servicio<'a> = PreferenciasService<'a, PgPreferenciasRepository, PgPasswordPolicyRepository>;

fn servicio(state: &AppState) -> Servicio<'_> {
    PreferenciasService { preferencias: &state.preferencias_usuario, password_policy: &state.password_policy }
}

fn a_response(p: Preferencias) -> PreferenciasResponse {
    PreferenciasResponse {
        locale: p.locale,
        theme: p.theme,
        clipboard_clear_minutes: p.clipboard_clear_minutes,
        auto_lock_minutes: p.auto_lock_minutes,
    }
}

pub async fn obtener(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<Json<PreferenciasResponse>, ApiError> {
    let p = servicio(&state).obtener(user.user_id).await?;
    Ok(Json(a_response(p)))
}

pub async fn actualizar(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(req): Json<ActualizarPreferenciasRequest>,
) -> Result<Json<PreferenciasResponse>, ApiError> {
    let nueva = Preferencias {
        locale: req.locale,
        theme: req.theme,
        clipboard_clear_minutes: req.clipboard_clear_minutes,
        auto_lock_minutes: req.auto_lock_minutes,
    };
    let p = servicio(&state).actualizar(user.user_id, nueva).await?;
    Ok(Json(a_response(p)))
}

/// `GET /me` — perfil de sólo lectura (F-01, no estaba expuesto).
pub async fn perfil(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<Json<PerfilResponse>, ApiError> {
    let p = PerfilService { perfil: &state.preferencias_usuario }.obtener(user.user_id).await?;
    Ok(Json(PerfilResponse {
        id: user.user_id,
        email: p.email,
        display_name: p.display_name,
        role: p.role,
        created_at: p.created_at,
        updated_at: p.updated_at,
        keys_created_at: p.keys_created_at,
    }))
}

/// `GET /me/permissions` (módulo 1, matriz RBAC) — conjunto resuelto de
/// permisos del usuario actual, usado por el frontend para ocultar/mostrar
/// UI (`esAdmin` deja de resolverse con el hack de probar `/admin/roles` y
/// mirar si da 403).
pub async fn permisos(State(state): State<AppState>, user: AuthenticatedUser) -> Result<Json<Vec<String>>, ApiError> {
    Ok(Json(state.roles.permisos_de_usuario(user.user_id).await.map_err(DomainError::from)?))
}

/// `GET /me/groups` — hallazgo real de uso 2026-08-11: no había forma de
/// que un usuario viera en su propio perfil a qué grupos pertenece ni si
/// es admin de alguno.
pub async fn grupos(
    State(state): State<AppState>,
    user: AuthenticatedUser,
) -> Result<Json<Vec<super::dto::GrupoDeUsuarioResponse>>, ApiError> {
    use crate::groups::repository::GroupMemberRepository;
    let grupos = state.miembros_de_grupo.grupos_de(user.user_id).await.map_err(DomainError::from)?;
    Ok(Json(
        grupos
            .into_iter()
            .map(|g| super::dto::GrupoDeUsuarioResponse { group_id: g.group_id, name: g.name, is_admin: g.is_admin })
            .collect(),
    ))
}

/// `GET /me/avatar` — `404` si no tiene avatar cargado, nunca un `200` con
/// body vacío (evita que el cliente tenga que distinguir "vacío" de "no
/// existe" a partir del content-length).
pub async fn avatar_obtener(State(state): State<AppState>, user: AuthenticatedUser) -> Result<impl IntoResponse, ApiError> {
    let avatar = AvatarService { avatar: &state.preferencias_usuario }.obtener(user.user_id).await?;
    match avatar {
        Some(a) => Ok(([(header::CONTENT_TYPE, a.content_type)], a.bytes).into_response()),
        None => Err(ApiError::from(DomainError::NotFound)),
    }
}

pub async fn avatar_actualizar(
    State(state): State<AppState>,
    user: AuthenticatedUser,
    Json(req): Json<ActualizarAvatarRequest>,
) -> Result<(), ApiError> {
    let bytes =
        b64::decode(&req.avatar_b64).map_err(|_| DomainError::ValidacionInvalida("avatar_b64 inválido".into()))?;
    AvatarService { avatar: &state.preferencias_usuario }
        .actualizar(user.user_id, Avatar { bytes, content_type: req.content_type })
        .await?;
    Ok(())
}

pub async fn avatar_eliminar(State(state): State<AppState>, user: AuthenticatedUser) -> Result<(), ApiError> {
    AvatarService { avatar: &state.preferencias_usuario }.eliminar(user.user_id).await?;
    Ok(())
}

/// `POST /me/change-passphrase` (F-01) — el cliente ya abrió el blob viejo
/// con la passphrase actual y lo re-selló con la nueva antes de llamar acá
/// (`$lib/crypto/identity.ts::cambiarPassphrase`); el servidor nunca ve
/// ninguna de las dos passphrases, sólo el blob ya re-sellado.
///
/// `SesionValida` (no `AuthenticatedUser`): quien llega hasta acá ya
/// demostró conocer la passphrase actual (la firma Ed25519 de
/// `/auth/verify` exige haberla desbloqueado client-side antes de firmar),
/// así que una sesión parcial también puede cambiarla — es justo lo que
/// necesita `RequiereCambiarPassphrase` (passphrase provisoria creada por un
/// admin) para no tener que abrir un endpoint nuevo sólo para ese caso.
pub async fn cambiar_passphrase(
    State(state): State<AppState>,
    sesion: SesionValida,
    Json(req): Json<CambiarPassphraseRequest>,
) -> Result<(), ApiError> {
    let encrypted_private_key_blob = b64::decode(&req.encrypted_private_key_blob_b64)
        .map_err(|_| DomainError::ValidacionInvalida("encrypted_private_key_blob_b64 inválido".into()))?;
    let private_key_nonce = b64::decode(&req.private_key_nonce_b64)
        .map_err(|_| DomainError::ValidacionInvalida("private_key_nonce_b64 inválido".into()))?;
    let kdf_salt = b64::decode(&req.kdf_salt_b64)
        .map_err(|_| DomainError::ValidacionInvalida("kdf_salt_b64 inválido".into()))?;

    CambiarPassphraseService { claves: &state.preferencias_usuario, eventos: state.eventos.clone() }
        .actualizar(sesion.user_id, NuevaClavePrivada { encrypted_private_key_blob, private_key_nonce, kdf_salt })
        .await?;
    Ok(())
}
