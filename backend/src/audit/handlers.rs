// Autor: Athan Espinoza

use axum::extract::{Query, State};
use axum::http::header;
use axum::response::IntoResponse;
use axum::Json;

use crate::auth::extractor::AuditorUser;
use crate::error::{ApiError, DomainError};
use crate::state::AppState;

use super::dto::{AuditLogEntryResponse, AuditLogExportQuery, AuditLogPageResponse, AuditLogQuery};
use super::models::{AuditEventType, AuditLogEntry, FiltroAuditLog};
use super::repository::PgAuditLogRepository;
use super::service::AuditLogService;

type Servicio<'a> = AuditLogService<'a, PgAuditLogRepository>;

fn servicio(state: &AppState) -> Servicio<'_> {
    AuditLogService { audit_log: &state.audit_log }
}

fn resolver_event_type(raw: Option<String>) -> Result<Option<AuditEventType>, ApiError> {
    match raw {
        None => Ok(None),
        Some(s) => AuditEventType::from_db_str(&s)
            .map(Some)
            .ok_or_else(|| DomainError::ValidacionInvalida("event_type desconocido".into()).into()),
    }
}

fn a_response(e: AuditLogEntry) -> AuditLogEntryResponse {
    AuditLogEntryResponse {
        id: e.id,
        actor_user_id: e.actor_user_id,
        actor_email: e.actor_email,
        event_type: e.event_type,
        subject_type: e.subject_type,
        subject_id: e.subject_id,
        metadata: e.metadata,
        created_at: e.created_at,
    }
}

pub async fn listar(
    State(state): State<AppState>,
    _auditor: AuditorUser,
    Query(q): Query<AuditLogQuery>,
) -> Result<Json<AuditLogPageResponse>, ApiError> {
    let event_type = resolver_event_type(q.event_type)?;
    let filtro = FiltroAuditLog { actor_user_id: q.actor_user_id, event_type, desde: q.from, hasta: q.to };

    let pagina = servicio(&state).listar(filtro, q.cursor, q.limit).await?;
    Ok(Json(AuditLogPageResponse {
        items: pagina.items.into_iter().map(a_response).collect(),
        next_cursor: pagina.next_cursor,
    }))
}

/// Escapa un campo para una fila CSV (RFC 4180): entre comillas dobles si
/// contiene coma, comilla o salto de línea, duplicando comillas internas.
fn csv_campo(valor: &str) -> String {
    if valor.contains(',') || valor.contains('"') || valor.contains('\n') {
        format!("\"{}\"", valor.replace('"', "\"\""))
    } else {
        valor.to_string()
    }
}

fn a_fila_csv(e: &AuditLogEntry) -> String {
    let actor = e.actor_user_id.map(|u| u.to_string()).unwrap_or_default();
    let subject_type = e.subject_type.clone().unwrap_or_default();
    let subject_id = e.subject_id.map(|u| u.to_string()).unwrap_or_default();
    let metadata = e.metadata.to_string();
    format!(
        "{},{},{},{},{},{},{}\n",
        csv_campo(&e.id.to_string()),
        csv_campo(&actor),
        csv_campo(&e.event_type),
        csv_campo(&subject_type),
        csv_campo(&subject_id),
        csv_campo(&metadata),
        csv_campo(&e.created_at.to_string()),
    )
}

/// `GET /admin/audit-log/export` — F-13: NDJSON (default) o CSV para que un
/// colector externo (Splunk, Elastic, lo que use el operador) ingiera
/// incrementalmente. Ellkan nunca exporta activamente a nada, el operador
/// arma su propio pipeline contra este endpoint.
pub async fn exportar(
    State(state): State<AppState>,
    _auditor: AuditorUser,
    Query(q): Query<AuditLogExportQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let event_type = resolver_event_type(q.event_type)?;
    let filtro = FiltroAuditLog { actor_user_id: q.actor_user_id, event_type, desde: q.from, hasta: q.to };

    let entradas = servicio(&state).exportar(filtro).await?;

    match q.format.as_deref() {
        Some("csv") => {
            let mut cuerpo = String::from("id,actor_user_id,event_type,subject_type,subject_id,metadata,created_at\n");
            for e in &entradas {
                cuerpo.push_str(&a_fila_csv(e));
            }
            Ok(([(header::CONTENT_TYPE, "text/csv; charset=utf-8")], cuerpo))
        }
        None | Some("ndjson") => {
            let mut cuerpo = String::new();
            for e in &entradas {
                let linea = serde_json::to_string(&a_response(e.clone()))
                    .expect("AuditLogEntryResponse siempre serializa");
                cuerpo.push_str(&linea);
                cuerpo.push('\n');
            }
            Ok(([(header::CONTENT_TYPE, "application/x-ndjson; charset=utf-8")], cuerpo))
        }
        Some(_) => Err(DomainError::ValidacionInvalida("format debe ser ndjson o csv".into()).into()),
    }
}
