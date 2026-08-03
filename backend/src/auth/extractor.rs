// Autor: Athan Espinoza

//! Extractor de Axum para autenticación. Lee el header
//! `Authorization: Bearer <session_id>`, valida contra `SessionRepository`
//! (revocación + vencimiento + `security_stamp` vigente) y expone el
//! `user_id` autenticado a los handlers sin repetir este código en cada uno.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use uuid::Uuid;

use crate::error::{ApiError, DomainError};
use crate::state::AppState;

use super::repository::SessionRepository;

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
        let cabecera = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(DomainError::InvalidCredentials)?;

        let session_id: Uuid = cabecera.parse().map_err(|_| DomainError::InvalidCredentials)?;

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
