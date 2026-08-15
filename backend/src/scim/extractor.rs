// Autor: Athan Espinoza

//! F-18: SCIM se autentica con un bearer token dedicado (`scim_tokens`), no
//! con una sesión de usuario — el directorio externo no tiene passphrase ni
//! clave privada, sólo este token de aprovisionamiento.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use sha2::{Digest, Sha256};

use crate::error::{ApiError, DomainError};
use crate::state::AppState;

use super::repository::ScimTokenRepository;

pub struct ScimAuth;

impl FromRequestParts<AppState> for ScimAuth {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(DomainError::InvalidCredentials)?;

        let hash = Sha256::digest(token.as_bytes());
        let valido = state.scim_tokens.valido(&hash).await.map_err(DomainError::from)?;
        if !valido {
            return Err(DomainError::InvalidCredentials.into());
        }

        Ok(ScimAuth)
    }
}
