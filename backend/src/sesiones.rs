// Autor: Athan Espinoza

//! QA-21 (pendiente #110): sesiones abiertas, al estilo de "dispositivos
//! vinculados" de WhatsApp. Reemplaza la aprobación de un dispositivo nuevo
//! desde otro (F-37), que nacía sin sesión y entregaba una sesión completa
//! salteando MFA: entrar ya exige contraseña, verificación del dispositivo
//! por email (F-02) y MFA si la política lo pide, así que aprobar a mano era
//! un paso de más. En cambio, cada uno ve dónde tiene la sesión abierta y
//! puede cerrar cualquiera de las otras.
//!
//! Minimización (pendiente #21): de cada sesión se guarda sólo un nombre
//! corto del navegador y el sistema ("Chrome · Windows"), nunca el
//! User-Agent completo ni la IP.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::audit::models::{AuditEventType, EventoAuditoria};
use crate::auth::extractor::AuthenticatedUser;
use crate::error::{ApiError, DomainError, RepoError};
use crate::eventos::DomainEvent;
use crate::state::AppState;

/// Nombre corto para mostrar: navegador o cliente, y sistema.
pub fn nombre_dispositivo(user_agent: &str) -> String {
    let ua = user_agent;
    let cliente = if ua.starts_with("ellkan-cli") {
        "Ellkan CLI"
    } else if ua.contains("Ellkan") || ua.contains("Tauri") {
        "Ellkan (escritorio)"
    } else if ua.contains("Edg/") {
        "Edge"
    } else if ua.contains("OPR/") || ua.contains("Opera") {
        "Opera"
    } else if ua.contains("Firefox/") {
        "Firefox"
    } else if ua.contains("Chrome/") || ua.contains("Chromium/") {
        "Chrome"
    } else if ua.contains("Safari/") {
        "Safari"
    } else {
        "Otro cliente"
    };
    let sistema = if ua.contains("Android") {
        Some("Android")
    } else if ua.contains("iPhone") || ua.contains("iPad") {
        Some("iOS")
    } else if ua.contains("Windows") {
        Some("Windows")
    } else if ua.contains("Mac OS X") || ua.contains("Macintosh") {
        Some("macOS")
    } else if ua.contains("CrOS") {
        Some("ChromeOS")
    } else if ua.contains("Linux") {
        Some("Linux")
    } else {
        None
    };
    match sistema {
        Some(s) => format!("{cliente} · {s}"),
        None => cliente.to_string(),
    }
}

/// Anota el uso de la sesión, a lo sumo una vez por minuto y sin demorar la
/// solicitud. Lo llama `AuthenticatedUser` al validar.
pub fn registrar_uso(pool: &sqlx::PgPool, session_id: Uuid, headers: &HeaderMap) {
    let dispositivo = headers.get(axum::http::header::USER_AGENT).and_then(|v| v.to_str().ok()).map(nombre_dispositivo);
    let pool = pool.clone();
    tokio::spawn(async move {
        let resultado = sqlx::query(
            "update sessions set last_used_at = now(), dispositivo = coalesce($2, dispositivo)
             where id = $1 and (last_used_at is null or last_used_at < now() - interval '1 minute')",
        )
        .bind(session_id)
        .bind(dispositivo)
        .execute(&pool)
        .await;
        if let Err(e) = resultado {
            tracing::warn!(error = %e, "no se pudo anotar el uso de la sesión");
        }
    });
}

#[derive(Debug, Serialize)]
pub struct SesionResponse {
    pub id: Uuid,
    /// `None` si la sesión todavía no hizo ninguna solicitud autenticada.
    pub dispositivo: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub creada: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub ultimo_uso: Option<OffsetDateTime>,
    /// La sesión desde la que se hace la consulta.
    pub actual: bool,
}

#[derive(Debug, Serialize)]
pub struct CerradasResponse {
    pub cerradas: u64,
}

/// `GET /me/sessions` — sesiones completas vigentes del usuario.
pub async fn listar(State(state): State<AppState>, auth: AuthenticatedUser) -> Result<Json<Vec<SesionResponse>>, ApiError> {
    let filas: Vec<(Uuid, Option<String>, OffsetDateTime, Option<OffsetDateTime>)> = sqlx::query_as(
        "select s.id, s.dispositivo, s.created_at, s.last_used_at
         from sessions s join users u on u.id = s.user_id
         where s.user_id = $1 and s.revoked_at is null and s.expires_at > now()
           and s.proposito = 'completa' and s.security_stamp = u.security_stamp
         order by coalesce(s.last_used_at, s.created_at) desc",
    )
    .bind(auth.user_id)
    .fetch_all(&state.pool)
    .await
    .map_err(|e| DomainError::from(RepoError::from(e)))?;
    Ok(Json(
        filas
            .into_iter()
            .map(|(id, dispositivo, creada, ultimo_uso)| SesionResponse {
                id,
                dispositivo,
                creada,
                ultimo_uso,
                actual: id == auth.session_id,
            })
            .collect(),
    ))
}

/// `DELETE /me/sessions/{id}` — cierra una sesión propia (también la actual,
/// que equivale a salir). 404 si no es del usuario o ya estaba cerrada.
pub async fn cerrar(State(state): State<AppState>, auth: AuthenticatedUser, Path(id): Path<Uuid>) -> Result<(), ApiError> {
    let resultado = sqlx::query("update sessions set revoked_at = now() where id = $1 and user_id = $2 and revoked_at is null")
        .bind(id)
        .bind(auth.user_id)
        .execute(&state.pool)
        .await
        .map_err(|e| DomainError::from(RepoError::from(e)))?;
    if resultado.rows_affected() == 0 {
        return Err(DomainError::NotFound.into());
    }
    auditar(&state, auth.user_id, serde_json::json!({ "session_id": id }));
    Ok(())
}

/// `POST /me/sessions/close-others` — cierra todas menos la actual.
pub async fn cerrar_otras(State(state): State<AppState>, auth: AuthenticatedUser) -> Result<Json<CerradasResponse>, ApiError> {
    let resultado = sqlx::query("update sessions set revoked_at = now() where user_id = $1 and id <> $2 and revoked_at is null")
        .bind(auth.user_id)
        .bind(auth.session_id)
        .execute(&state.pool)
        .await
        .map_err(|e| DomainError::from(RepoError::from(e)))?;
    let cerradas = resultado.rows_affected();
    auditar(&state, auth.user_id, serde_json::json!({ "otras_sesiones": cerradas }));
    Ok(Json(CerradasResponse { cerradas }))
}

fn auditar(state: &AppState, user_id: Uuid, detalle: serde_json::Value) {
    let _ = state.eventos.send(DomainEvent::Auditoria(
        EventoAuditoria::nuevo(AuditEventType::AuthLogout, Some(user_id))
            .con_sujeto("user", user_id)
            .con_metadata(detalle),
    ));
}

#[cfg(test)]
mod tests {
    use super::nombre_dispositivo;

    #[test]
    fn nombres_cortos_de_navegadores_y_clientes() {
        let casos = [
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36",
                "Chrome · Windows",
            ),
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36 Edg/141.0",
                "Edge · Windows",
            ),
            (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
                "Safari · macOS",
            ),
            ("Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0", "Firefox · Linux"),
            (
                "Mozilla/5.0 (Linux; Android 15) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Mobile Safari/537.36",
                "Chrome · Android",
            ),
            (
                "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 Version/18.1 Mobile Safari/604.1",
                "Safari · iOS",
            ),
            ("ellkan-cli/0.1.70", "Ellkan CLI"),
            ("curl/8.0", "Otro cliente"),
        ];
        for (ua, esperado) in casos {
            assert_eq!(nombre_dispositivo(ua), esperado, "{ua}");
        }
    }
}
