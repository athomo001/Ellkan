// Autor: Athan Espinoza

//! Extractor de Axum para autenticación. Lee el header
//! `Authorization: Bearer <session_id>`, valida contra `SessionRepository`
//! (revocación + vencimiento + `security_stamp` vigente) y expone el
//! `user_id` autenticado a los handlers sin repetir este código en cada uno.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use uuid::Uuid;

use crate::admin::repository::RoleRepository;
use crate::error::{ApiError, DomainError};
use crate::state::AppState;

use super::repository::SessionRepository;

fn extraer_session_id(parts: &Parts) -> Result<Uuid, ApiError> {
    let cabecera = parts
        .headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(DomainError::InvalidCredentials)?;

    cabecera.parse().map_err(|_| DomainError::InvalidCredentials.into())
}

pub struct AuthenticatedUser {
    pub session_id: Uuid,
    pub user_id: Uuid,
}

impl FromRequestParts<AppState> for AuthenticatedUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let session_id = extraer_session_id(parts)?;

        let user_id = state
            .sesiones
            .validar(session_id)
            .await
            .map_err(DomainError::from)?
            .ok_or(DomainError::InvalidCredentials)?;

        // Redacción de spans: el span de la request ya existe (`make_span_with`
        // en `lib.rs`), acá sólo se le agrega el `actor_id` una vez que la
        // sesión es válida.
        tracing::Span::current().record("actor_id", user_id.to_string());

        Ok(AuthenticatedUser { session_id, user_id })
    }
}

/// F-14: sesión válida (no revocada, no vencida, `security_stamp` vigente)
/// **sin exigir `mfa_verified_at`** — a diferencia de `AuthenticatedUser`,
/// que sí lo exige y por eso es el único extractor que usa el resto de la
/// API. Sólo tres endpoints necesitan aceptar una sesión todavía parcial:
/// verificar el código MFA y configurar un segundo factor por primera vez
/// (`mfa::handlers`) — ahí es exactamente donde una sesión sin MFA
/// verificado tiene que poder operar, no en ningún otro lado.
pub struct SesionValida {
    pub session_id: Uuid,
    pub user_id: Uuid,
}

impl FromRequestParts<AppState> for SesionValida {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let session_id = extraer_session_id(parts)?;

        let user_id = state
            .sesiones
            .validar_cualquiera(session_id)
            .await
            .map_err(DomainError::from)?
            .ok_or(DomainError::InvalidCredentials)?;

        tracing::Span::current().record("actor_id", user_id.to_string());

        Ok(SesionValida { session_id, user_id })
    }
}

/// Envuelve `AuthenticatedUser` y además exige el permiso comodín `"*"`
/// (rol `admin` de organización, F-22 adelantado — ver
/// `spec/05-plan-de-implementacion.md`). Para autoridad delegada de grupo
/// (F-12, "¿es manager de este subárbol puntual?") el chequeo vive en
/// `GroupService`, no acá — esa pregunta depende del `group_id` del path, no
/// es una propiedad estática de la sesión.
pub struct AdminUser {
    pub user_id: Uuid,
}

impl FromRequestParts<AppState> for AdminUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let autenticado = AuthenticatedUser::from_request_parts(parts, state).await?;

        let es_admin = state
            .roles
            .usuario_tiene_permiso(autenticado.user_id, "*")
            .await
            .map_err(DomainError::from)?;

        if !es_admin {
            return Err(DomainError::PermissionDenied.into());
        }

        Ok(AdminUser { user_id: autenticado.user_id })
    }
}

/// F-13: exige el permiso granular `audit_log.read` — a diferencia de
/// `AdminUser` (comodín `"*"`), esto también deja pasar al rol `auditor`
/// sembrado en el catálogo de roles, que no tiene ningún otro privilegio
/// administrativo. `usuario_tiene_permiso` ya resuelve `"*"` como superset,
/// así que un admin de organización también puede leer el audit log sin
/// necesidad de un segundo chequeo.
pub struct AuditorUser {
    pub user_id: Uuid,
}

impl FromRequestParts<AppState> for AuditorUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let autenticado = AuthenticatedUser::from_request_parts(parts, state).await?;

        let autorizado = state
            .roles
            .usuario_tiene_permiso(autenticado.user_id, "audit_log.read")
            .await
            .map_err(DomainError::from)?;

        if !autorizado {
            return Err(DomainError::PermissionDenied.into());
        }

        Ok(AuditorUser { user_id: autenticado.user_id })
    }
}
