// Autor: Athan Espinoza

use axum::extract::{Path, Query, State};
use axum::Json;

use crate::auth::extractor::AdminUser;
use crate::error::{ApiError, DomainError};
use crate::state::AppState;

use super::dto::{
    ListarReporteQuery, MfaCoverageItem, PasswordExpiradoItem, RecursoSinRotarItem, ReportResponse,
    UsuarioInactivoItem,
};
use super::models::ReportId;
use super::service::ReportsService;

type Servicio<'a> = ReportsService<'a, super::repository::PgReportsRepository, crate::password_policy::repository::PgPasswordPolicyRepository>;

fn servicio(state: &AppState) -> Servicio<'_> {
    ReportsService { reportes: &state.reportes, password_policy: &state.password_policy }
}

/// `GET /admin/reports/{reportId}` — `reportId` fuera del enum cerrado es
/// `404`, nunca un reporte vacío (criterio de aceptación literal de F-23).
pub async fn obtener(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(report_id): Path<String>,
    Query(q): Query<ListarReporteQuery>,
) -> Result<Json<ReportResponse>, ApiError> {
    let report_id = ReportId::from_slug(&report_id).ok_or(DomainError::NotFound)?;
    let servicio = servicio(&state);

    let respuesta = match report_id {
        ReportId::PasswordsExpired => {
            let (filas, next_cursor) = servicio.passwords_expired(q.cursor, None).await?;
            ReportResponse::PasswordsExpired {
                items: filas
                    .into_iter()
                    .map(|f| PasswordExpiradoItem { user_id: f.user_id, email: f.email, passphrase_set_at: f.passphrase_set_at })
                    .collect(),
                next_cursor,
            }
        }
        ReportId::MfaCoverage => {
            let (filas, next_cursor) = servicio.mfa_coverage(q.cursor, None).await?;
            ReportResponse::MfaCoverage {
                items: filas
                    .into_iter()
                    .map(|f| MfaCoverageItem { user_id: f.user_id, email: f.email, mfa_enabled: f.mfa_enabled })
                    .collect(),
                next_cursor,
            }
        }
        ReportId::InactiveUsers => {
            let (filas, next_cursor) = servicio.inactive_users(q.days, q.cursor, None).await?;
            ReportResponse::InactiveUsers {
                items: filas
                    .into_iter()
                    .map(|f| UsuarioInactivoItem { user_id: f.user_id, email: f.email, last_login_at: f.last_login_at })
                    .collect(),
                next_cursor,
            }
        }
        ReportId::ResourcesNeverRotated => {
            let (filas, next_cursor) = servicio.resources_never_rotated(q.days, q.cursor, None).await?;
            ReportResponse::ResourcesNeverRotated {
                items: filas
                    .into_iter()
                    .map(|f| RecursoSinRotarItem { resource_id: f.resource_id, created_by: f.created_by, created_at: f.created_at })
                    .collect(),
                next_cursor,
            }
        }
    };

    Ok(Json(respuesta))
}
