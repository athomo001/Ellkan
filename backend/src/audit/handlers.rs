// Autor: Athan Espinoza

use axum::Json;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::IntoResponse;

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

fn a_fila_csv(e: &AuditLogEntry) -> String {
    let actor = e.actor_user_id.map(|u| u.to_string()).unwrap_or_default();
    let subject_type = e.subject_type.clone().unwrap_or_default();
    let subject_id = e.subject_id.map(|u| u.to_string()).unwrap_or_default();
    let metadata = e.metadata.to_string();
    format!(
        "{},{},{},{},{},{},{}\n",
        crate::csv_seguro::campo(&e.id.to_string()),
        crate::csv_seguro::campo(&actor),
        crate::csv_seguro::campo(&e.event_type),
        crate::csv_seguro::campo(&subject_type),
        crate::csv_seguro::campo(&subject_id),
        crate::csv_seguro::campo(&metadata),
        crate::csv_seguro::campo(&e.created_at.to_string()),
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

    let tanda = servicio(&state).exportar(filtro, q.after).await?;

    let (tipo, cuerpo) = match q.format.as_deref() {
        Some("csv") => {
            let mut cuerpo = String::from("id,actor_user_id,event_type,subject_type,subject_id,metadata,created_at\n");
            for e in &tanda.items {
                cuerpo.push_str(&a_fila_csv(e));
            }
            ("text/csv; charset=utf-8", cuerpo)
        }
        None | Some("ndjson") => {
            let mut cuerpo = String::new();
            for e in &tanda.items {
                let linea = serde_json::to_string(&a_response(e.clone())).expect("AuditLogEntryResponse siempre serializa");
                cuerpo.push_str(&linea);
                cuerpo.push('\n');
            }
            ("application/x-ndjson; charset=utf-8", cuerpo)
        }
        Some(_) => return Err(DomainError::ValidacionInvalida("format debe ser ndjson o csv".into()).into()),
    };

    // QA-40: si quedan eventos se avisa y se da con qué seguir (`?after=`),
    // en vez de cortar en silencio. `X-Ellkan-Truncated` va siempre, para que
    // el colector no tenga que inferirlo.
    let mut cabeceras = HeaderMap::new();
    cabeceras.insert(header::CONTENT_TYPE, HeaderValue::from_static(tipo));
    cabeceras.insert(
        "x-ellkan-truncated",
        HeaderValue::from_static(if tanda.next_cursor.is_some() { "true" } else { "false" }),
    );
    if let Some(cursor) = tanda.next_cursor {
        cabeceras.insert(
            "x-ellkan-next-cursor",
            HeaderValue::from_str(&cursor.to_string()).expect("un uuid es un header válido"),
        );
    }
    Ok((cabeceras, cuerpo))
}
