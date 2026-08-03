// Autor: Athan Espinoza

//! Un tipo de error por capa, un envelope JSON único. `RepoError` nunca se
//! expone tal cual a un cliente HTTP; `DomainError` implementa
//! `From<RepoError>`; `ApiError` implementa `IntoResponse` y es el único
//! punto que decide qué llega al cliente.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum RepoError {
    #[error("conflicto de estado")]
    Conflict,
    #[error("error de base de datos: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum DomainError {
    #[error("recurso no encontrado")]
    NotFound,
    #[error("conflicto de estado")]
    Conflict,
    #[error("credenciales inválidas")]
    InvalidCredentials,
    #[error("permiso denegado")]
    PermissionDenied,
    #[error("entrada inválida: {0}")]
    ValidacionInvalida(String),
    #[error("demasiadas solicitudes")]
    RateLimited,
    /// F-06: un recurso con metadata personal (`metadata_key_type =
    /// 'user_key'`) no puede compartirse — sólo los cifrados con la
    /// metadata key compartida.
    #[error("un recurso con metadata personal no puede compartirse")]
    MetadataPersonalNoCompartible,
    /// F-12: re-parentar un grupo de forma que quede como su propio
    /// ancestro.
    #[error("ese movimiento crearía un ciclo en el árbol de grupos")]
    CicloDeGrupo,
    /// F-12: no puede borrarse un grupo con subgrupos sin re-ubicarlos o
    /// borrarlos primero.
    #[error("el grupo tiene subgrupos, no puede borrarse directamente")]
    GrupoTieneSubgrupos,
    /// F-12: no puede borrarse un grupo que sea único Owner de un recurso o
    /// carpeta compartida.
    #[error("el grupo es único Owner de al menos un recurso/carpeta compartida")]
    GrupoEsUnicoOwner,
    /// F-12: regla distinta a `GrupoEsUnicoOwner` — ésta es sobre quién
    /// puede seguir administrando el grupo en sí, no sobre ownership de
    /// recursos.
    #[error("no se puede quitar ni degradar al único manager de un grupo con miembros")]
    UnicoManagerDeGrupo,
    #[error("error interno")]
    Interno(#[from] RepoError),
}

/// Envelope de error único para los tres clientes (web, extensión, CLI).
#[derive(Debug, Serialize)]
struct ErrorBody {
    error: ErrorDetalle,
}

#[derive(Debug, Serialize)]
struct ErrorDetalle {
    code: &'static str,
    message: String,
    request_id: String,
}

pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self { status, code, message: message.into() }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        // request_id propio de esta respuesta — en producción se correlaciona
        // con el span de OpenTelemetry; acá basta con un id nuevo por
        // respuesta para no perder el punto de enganche cuando se conecte
        // tracing completo.
        let body = ErrorBody {
            error: ErrorDetalle {
                code: self.code,
                message: self.message,
                request_id: Uuid::now_v7().to_string(),
            },
        };
        (self.status, Json(body)).into_response()
    }
}

impl From<DomainError> for ApiError {
    fn from(err: DomainError) -> Self {
        match err {
            DomainError::NotFound => {
                ApiError::new(StatusCode::NOT_FOUND, "NOT_FOUND", "no encontrado")
            }
            DomainError::Conflict => {
                ApiError::new(StatusCode::CONFLICT, "CONFLICT", "conflicto de estado")
            }
            // Nunca distinguir "usuario no existe" de "credenciales inválidas"
            // — anti user-enumeration.
            DomainError::InvalidCredentials => ApiError::new(
                StatusCode::UNAUTHORIZED,
                "INVALID_CREDENTIALS",
                "credenciales inválidas",
            ),
            DomainError::PermissionDenied => ApiError::new(
                StatusCode::FORBIDDEN,
                "PERMISSION_DENIED",
                "no tenés permiso para esta acción",
            ),
            DomainError::ValidacionInvalida(detalle) => {
                ApiError::new(StatusCode::BAD_REQUEST, "INVALID_INPUT", detalle)
            }
            DomainError::RateLimited => ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "RATE_LIMITED",
                "demasiadas solicitudes, esperá antes de reintentar",
            ),
            DomainError::MetadataPersonalNoCompartible => ApiError::new(
                StatusCode::BAD_REQUEST,
                "METADATA_PERSONAL_NO_COMPARTIBLE",
                "un recurso con metadata personal no puede compartirse",
            ),
            DomainError::CicloDeGrupo => ApiError::new(
                StatusCode::BAD_REQUEST,
                "GROUP_CYCLE",
                "ese movimiento crearía un ciclo en el árbol de grupos",
            ),
            DomainError::GrupoTieneSubgrupos => ApiError::new(
                StatusCode::CONFLICT,
                "GROUP_HAS_SUBGROUPS",
                "el grupo tiene subgrupos, no puede borrarse directamente",
            ),
            DomainError::GrupoEsUnicoOwner => ApiError::new(
                StatusCode::CONFLICT,
                "GROUP_SOLE_OWNER",
                "el grupo es único Owner de al menos un recurso/carpeta compartida",
            ),
            DomainError::UnicoManagerDeGrupo => ApiError::new(
                StatusCode::CONFLICT,
                "GROUP_SOLE_MANAGER",
                "no se puede quitar ni degradar al único manager de un grupo con miembros",
            ),
            // Todo error no mapeado explícitamente cae acá — nunca se filtra
            // el mensaje real de sqlx::Error ni un panic al cliente.
            DomainError::Interno(_) => ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "error interno",
            ),
        }
    }
}
