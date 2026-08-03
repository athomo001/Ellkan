// Autor: Athan Espinoza

//! Rate limiting por usuario autenticado: la API completa tiene un límite
//! base por IP (`tower_governor` en `lib.rs`) **y** por usuario autenticado,
//! uno no reemplaza al otro. Corre como middleware sobre las rutas ya
//! protegidas por sesión, porque `GovernorLayer` (un `tower::Layer` puro) no
//! tiene forma de extraer `AuthenticatedUser` antes de que exista el handler.

use axum::extract::{FromRequestParts, Request, State};
use axum::middleware::Next;
use axum::response::Response;

use crate::auth::extractor::AuthenticatedUser;
use crate::error::{ApiError, DomainError};
use crate::state::AppState;

pub async fn limitar_por_usuario(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let (mut parts, body) = req.into_parts();
    let usuario = AuthenticatedUser::from_request_parts(&mut parts, &state).await?;

    if state.limitador_por_usuario.check_key(&usuario.user_id).is_err() {
        return Err(DomainError::RateLimited.into());
    }

    let req = Request::from_parts(parts, body);
    Ok(next.run(req).await)
}
