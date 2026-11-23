// Autor: Athan Espinoza

//! Service del aviso de versión nueva — nunca importa `axum`.

use std::time::Duration;

use uuid::Uuid;

use crate::audit::models::{AuditEventType, EventoAuditoria};
use crate::error::DomainError;
use crate::eventos::{DomainEvent, EmisorDeEventos};

use super::models::{EstadoAviso, UltimaVersion, parsear_version};
use super::repository::UpdateCheckRepository;

/// API pública de Releases del repo. Se puede cambiar con
/// `ELLKAN_UPDATE_CHECK_URL` (un mirror interno, o los tests).
const URL_POR_DEFECTO: &str = "https://api.github.com/repos/athomo001/ellkan/releases/latest";
/// Tope de lo que se lee de la respuesta: la de GitHub pesa unos KB.
const MAX_RESPUESTA: usize = 1024 * 1024;

pub fn url_de_consulta() -> String {
    std::env::var("ELLKAN_UPDATE_CHECK_URL")
        .ok()
        .filter(|u| !u.trim().is_empty())
        .unwrap_or_else(|| URL_POR_DEFECTO.to_string())
}

/// Lee `tag_name` y `html_url` de la respuesta de GitHub y los valida: sólo
/// se guarda una versión `X.Y.Z` y un link `https://` (el frontend lo
/// muestra como enlace). Con `ELLKAN_UPDATE_CHECK_URL` por defecto, el link
/// tiene que ser de `github.com`.
pub fn interpretar_respuesta(cuerpo: &[u8], exigir_github: bool) -> Option<UltimaVersion> {
    #[derive(serde::Deserialize)]
    struct Release {
        tag_name: String,
        html_url: String,
    }
    let r: Release = serde_json::from_slice(cuerpo).ok()?;
    parsear_version(&r.tag_name)?;
    let url_ok = if exigir_github {
        r.html_url.starts_with("https://github.com/")
    } else {
        r.html_url.starts_with("https://") || r.html_url.starts_with("http://")
    };
    if !url_ok || r.html_url.len() > 512 || r.html_url.chars().any(char::is_control) {
        return None;
    }
    Some(UltimaVersion { version: r.tag_name.trim_start_matches('v').to_string(), url: r.html_url })
}

/// Un `GET` anónimo a la URL de consulta. Sin cookies ni redirecciones, con
/// tiempo límite y `User-Agent` genérico (GitHub lo exige).
pub async fn consultar_ultima_version() -> Result<UltimaVersion, String> {
    let url = url_de_consulta();
    let cliente = openidconnect::reqwest::Client::builder()
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .user_agent("ellkan-server")
        .build()
        .map_err(|e| format!("cliente HTTP: {e}"))?;
    let resp = cliente
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|e| format!("consulta: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("respuesta {}", resp.status()));
    }
    let cuerpo = resp.bytes().await.map_err(|e| format!("lectura: {e}"))?;
    if cuerpo.len() > MAX_RESPUESTA {
        return Err("respuesta demasiado grande".into());
    }
    interpretar_respuesta(&cuerpo, url == URL_POR_DEFECTO).ok_or_else(|| "respuesta sin versión válida".into())
}

pub struct UpdateCheckService<'a, R> {
    pub repo: &'a R,
    pub eventos: EmisorDeEventos,
}

impl<R> UpdateCheckService<'_, R>
where
    R: UpdateCheckRepository,
{
    pub async fn obtener(&self) -> Result<EstadoAviso, DomainError> {
        Ok(self.repo.obtener().await?)
    }

    pub async fn fijar_habilitado(&self, actor_id: Uuid, enabled: bool) -> Result<EstadoAviso, DomainError> {
        self.repo.fijar_habilitado(enabled).await?;
        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::UpdateCheckUpdated, Some(actor_id))
                .con_metadata(serde_json::json!({ "enabled": enabled })),
        ));
        Ok(self.repo.obtener().await?)
    }

    /// Consulta y guarda, sólo si el aviso está activo. Un fallo de red se
    /// registra en el log y no toca lo guardado.
    pub async fn consultar_si_corresponde(&self) -> Result<(), DomainError> {
        if !self.repo.obtener().await?.enabled {
            return Ok(());
        }
        match consultar_ultima_version().await {
            Ok(ultima) => self.repo.guardar_resultado(&ultima).await?,
            Err(e) => tracing::warn!("aviso de versión: no se pudo consultar la última versión: {e}"),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toma_versión_y_link_válidos() {
        let ok = br#"{"tag_name":"v0.2.0","html_url":"https://github.com/athomo001/ellkan/releases/tag/v0.2.0","body":"..."}"#;
        let u = interpretar_respuesta(ok, true).unwrap();
        assert_eq!(u.version, "0.2.0");
        assert!(u.url.ends_with("/v0.2.0"));
    }

    #[test]
    fn descarta_lo_que_no_es_una_release_estable() {
        for malo in [
            &br#"{"tag_name":"v0.2.0-dev.5","html_url":"https://github.com/x"}"#[..],
            br#"{"tag_name":"v0.2.0","html_url":"javascript:alert(1)"}"#,
            br#"{"tag_name":"v0.2.0","html_url":"https://otro.com/x"}"#,
            br#"{"message":"Not Found"}"#,
            b"no es json",
        ] {
            assert!(interpretar_respuesta(malo, true).is_none(), "{}", String::from_utf8_lossy(malo));
        }
        // Con una URL propia (mirror), el link puede ser de otro dominio.
        assert!(interpretar_respuesta(br#"{"tag_name":"v0.2.0","html_url":"https://otro.com/x"}"#, false).is_some());
    }
}
