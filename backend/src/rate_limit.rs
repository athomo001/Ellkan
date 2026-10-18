// Autor: Athan Espinoza

//! Rate limiting de la API: un único middleware que decide, request por
//! request, contra qué cupo cuenta.
//!
//! - **Con sesión válida** → cupo del usuario (`limitador_por_usuario`).
//! - **Sin sesión, o con una inválida** → cupo de la IP (`limitador_por_ip`).
//!
//! Antes (hasta 2026-10-17) el límite por IP (`GovernorLayer`) se aplicaba a
//! TODO, también a usuarios autenticados. Detrás de Docker o de la NAT de una
//! oficina todos los clientes llegan con la misma IP: la app de escritorio
//! subiendo un respaldo dejaba sin servicio a la web del mismo usuario, y 50
//! personas en una oficina se habrían bloqueado entre ellas.
//!
//! Un token inventado no sirve para saltarse el límite por IP (lo que frena
//! fuerza bruta en el login): sólo una sesión que valida contra la base pasa
//! al cupo por usuario.

use axum::extract::{ConnectInfo, FromRequestParts, Request, State};
use axum::middleware::Next;
use axum::response::Response;

use crate::auth::extractor::{AuthenticatedUser, SesionValida};
use crate::error::{ApiError, DomainError};
use crate::state::AppState;

pub async fn limitar_solicitudes(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let (mut parts, body) = req.into_parts();

    let usuario = if parts.headers.contains_key(axum::http::header::AUTHORIZATION) {
        AuthenticatedUser::from_request_parts(&mut parts, &state).await.ok()
    } else {
        None
    };

    match usuario {
        Some(usuario) => {
            if state.limitador_por_usuario.check_key(&usuario.user_id).is_err() {
                tracing::warn!(limite = "usuario", user_id = %usuario.user_id, "límite de solicitudes por usuario agotado");
                return Err(DomainError::RateLimited.into());
            }
            // El extractor del handler la reusa en vez de validar otra vez.
            parts.extensions.insert(usuario);
        }
        None => {
            // Sin `ConnectInfo` (tests que llaman al router directo, sin
            // `into_make_service_with_connect_info`) no hay IP que limitar.
            if let Some(ConnectInfo(addr)) = parts.extensions.get::<ConnectInfo<std::net::SocketAddr>>()
                && state.limitador_por_ip.check_key(&addr.ip()).is_err()
            {
                tracing::warn!(limite = "ip", "límite de solicitudes por IP agotado");
                return Err(DomainError::RateLimited.into());
            }
        }
    }

    let req = Request::from_parts(parts, body);
    Ok(next.run(req).await)
}

/// F-14: rate limit dedicado sobre `POST /auth/mfa/verify`, keyed por sesión
/// parcial — más estricto que el general (`limitar_por_usuario`), porque un
/// código TOTP de 6 dígitos tiene espacio de búsqueda acotado y este
/// endpoint puntual lo necesita antes de agotarlo (hallazgo real de
/// Passbolt citado en la spec de F-14).
pub async fn limitar_mfa_por_sesion(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let (mut parts, body) = req.into_parts();
    let sesion = SesionValida::from_request_parts(&mut parts, &state).await?;

    if state.limitador_mfa.check_key(&sesion.session_id).is_err() {
        return Err(DomainError::RateLimited.into());
    }

    let req = Request::from_parts(parts, body);
    Ok(next.run(req).await)
}
