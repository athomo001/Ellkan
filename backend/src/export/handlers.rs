// Autor: Athan Espinoza

use axum::extract::{Query, State};
use axum::http::header;
use axum::response::IntoResponse;
use axum::Json;

use crate::admin::repository::PgRoleRepository;
use crate::auth::extractor::{AdminUser, AuthenticatedUser};
use crate::error::{ApiError, DomainError};
use crate::state::AppState;

use super::dto::{
    ActualizarExportPolicyRequest, ExportPolicyResponse, FormatoExportQuery, GrupoExportResponse,
    MiembroDeGrupoResponse, ReportarExportEventRequest, UsuarioExportResponse,
};
use super::models::{ExportPolicy, FilaExportGrupo, FilaExportUsuario, TipoEventoExport};
use super::repository::{PgExportPolicyRepository, PgExportRepository};
use super::service::ExportService;

type Servicio<'a> = ExportService<'a, PgExportPolicyRepository, PgExportRepository, PgRoleRepository>;

fn servicio(state: &AppState) -> Servicio<'_> {
    ExportService {
        policy: &state.export_policy,
        datos: &state.export_datos,
        roles: &state.roles,
        eventos: state.eventos.clone(),
    }
}

fn a_response_policy(p: ExportPolicy) -> ExportPolicyResponse {
    ExportPolicyResponse {
        export_enabled: p.export_enabled,
        allowed_formats: p.allowed_formats,
        import_enabled: p.import_enabled,
    }
}

/// `GET /export-policy` — cualquier usuario autenticado, necesita saber si
/// puede exportar/importar (y en qué formatos) antes de intentarlo.
pub async fn politica(
    State(state): State<AppState>,
    _usuario: AuthenticatedUser,
) -> Result<Json<ExportPolicyResponse>, ApiError> {
    Ok(Json(a_response_policy(servicio(&state).politica().await?)))
}

pub async fn politica_admin(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<ExportPolicyResponse>, ApiError> {
    Ok(Json(a_response_policy(servicio(&state).politica().await?)))
}

pub async fn actualizar_politica(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(req): Json<ActualizarExportPolicyRequest>,
) -> Result<Json<ExportPolicyResponse>, ApiError> {
    let nueva = ExportPolicy {
        export_enabled: req.export_enabled,
        allowed_formats: req.allowed_formats,
        import_enabled: req.import_enabled,
    };
    let actualizada = servicio(&state).actualizar_politica(admin.user_id, nueva).await?;
    Ok(Json(a_response_policy(actualizada)))
}

/// `POST /export-events` — ver `mod.rs`: éste es, a la vez, el registro de
/// auditoría y el único gate server-side real de F-27 (no hay un endpoint
/// separado que sirva el contenido a exportar, eso sigue siendo
/// `GET /resources`/`.../secret`).
pub async fn reportar_evento(
    State(state): State<AppState>,
    usuario: AuthenticatedUser,
    Json(req): Json<ReportarExportEventRequest>,
) -> Result<(), ApiError> {
    let tipo = match req.event_type.as_str() {
        "export" => TipoEventoExport::Export,
        "import" => TipoEventoExport::Import,
        _ => return Err(DomainError::ValidacionInvalida("event_type debe ser 'export' o 'import'".into()).into()),
    };
    servicio(&state)
        .reportar_evento(usuario.user_id, tipo, &req.format, req.resource_count)
        .await?;
    Ok(())
}

/// Neutraliza CSV injection (PBL-13-002, hallazgo real en Passbolt): un
/// campo que empiece con `=`/`+`/`-`/`@`/tab/CR se interpreta como fórmula
/// al abrir en Excel/Sheets — se antepone `'` sin excepción, además del
/// escapado RFC 4180 normal (comillas si hay coma/comilla/salto de línea).
fn csv_campo_seguro(valor: &str) -> String {
    let neutralizado = if valor.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{valor}")
    } else {
        valor.to_string()
    };
    if neutralizado.contains(',') || neutralizado.contains('"') || neutralizado.contains('\n') {
        format!("\"{}\"", neutralizado.replace('"', "\"\""))
    } else {
        neutralizado
    }
}

fn resolver_formato(raw: Option<&str>) -> Result<&'static str, ApiError> {
    match raw {
        None | Some("ndjson") => Ok("ndjson"),
        Some("csv") => Ok("csv"),
        Some(_) => Err(DomainError::ValidacionInvalida("format debe ser ndjson o csv".into()).into()),
    }
}

fn a_response_usuario(f: FilaExportUsuario) -> UsuarioExportResponse {
    UsuarioExportResponse {
        id: f.id,
        email: f.email,
        display_name: f.display_name,
        role: f.role,
        active: f.active,
        deleted_at: f.deleted_at,
        created_at: f.created_at,
        updated_at: f.updated_at,
        mfa_configured: f.mfa_configured,
        passkey_count: f.passkey_count,
        groups: f.groups,
        public_key_x25519_b64: f.public_key_x25519_b64,
    }
}

pub async fn exportar_usuarios(
    State(state): State<AppState>,
    admin: AdminUser,
    Query(q): Query<FormatoExportQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let formato = resolver_formato(q.format.as_deref())?;
    let filas = servicio(&state).listar_usuarios(admin.user_id).await?;

    if formato == "csv" {
        let mut cuerpo = String::from(
            "id,email,display_name,role,active,deleted_at,created_at,updated_at,mfa_configured,passkey_count,groups,public_key_x25519_b64\n",
        );
        for f in filas {
            let r = a_response_usuario(f);
            cuerpo.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{},{},{}\n",
                csv_campo_seguro(&r.id.to_string()),
                csv_campo_seguro(&r.email),
                csv_campo_seguro(&r.display_name),
                csv_campo_seguro(&r.role),
                r.active,
                csv_campo_seguro(&r.deleted_at.map(|d| d.to_string()).unwrap_or_default()),
                csv_campo_seguro(&r.created_at.to_string()),
                csv_campo_seguro(&r.updated_at.to_string()),
                r.mfa_configured,
                r.passkey_count,
                csv_campo_seguro(&r.groups.join(";")),
                csv_campo_seguro(&r.public_key_x25519_b64.unwrap_or_default()),
            ));
        }
        Ok(([(header::CONTENT_TYPE, "text/csv; charset=utf-8")], cuerpo).into_response())
    } else {
        let mut cuerpo = String::new();
        for f in filas {
            let linea = serde_json::to_string(&a_response_usuario(f)).expect("UsuarioExportResponse siempre serializa");
            cuerpo.push_str(&linea);
            cuerpo.push('\n');
        }
        Ok(([(header::CONTENT_TYPE, "application/x-ndjson; charset=utf-8")], cuerpo).into_response())
    }
}

fn a_response_grupo(f: FilaExportGrupo) -> GrupoExportResponse {
    GrupoExportResponse {
        id: f.id,
        name: f.name,
        parent_group_id: f.parent_group_id,
        deleted_at: f.deleted_at,
        members: f.members.into_iter().map(|m| MiembroDeGrupoResponse { user_id: m.user_id, is_admin: m.is_admin }).collect(),
    }
}

pub async fn exportar_grupos(
    State(state): State<AppState>,
    admin: AdminUser,
    Query(q): Query<FormatoExportQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let formato = resolver_formato(q.format.as_deref())?;
    let filas = servicio(&state).listar_grupos(admin.user_id).await?;

    if formato == "csv" {
        let mut cuerpo = String::from("id,name,parent_group_id,deleted_at,members\n");
        for f in filas {
            let r = a_response_grupo(f);
            let miembros = r
                .members
                .iter()
                .map(|m| format!("{}:{}", m.user_id, if m.is_admin { "admin" } else { "member" }))
                .collect::<Vec<_>>()
                .join(";");
            cuerpo.push_str(&format!(
                "{},{},{},{},{}\n",
                csv_campo_seguro(&r.id.to_string()),
                csv_campo_seguro(&r.name),
                csv_campo_seguro(&r.parent_group_id.map(|p| p.to_string()).unwrap_or_default()),
                csv_campo_seguro(&r.deleted_at.map(|d| d.to_string()).unwrap_or_default()),
                csv_campo_seguro(&miembros),
            ));
        }
        Ok(([(header::CONTENT_TYPE, "text/csv; charset=utf-8")], cuerpo).into_response())
    } else {
        let mut cuerpo = String::new();
        for f in filas {
            let linea = serde_json::to_string(&a_response_grupo(f)).expect("GrupoExportResponse siempre serializa");
            cuerpo.push_str(&linea);
            cuerpo.push('\n');
        }
        Ok(([(header::CONTENT_TYPE, "application/x-ndjson; charset=utf-8")], cuerpo).into_response())
    }
}
