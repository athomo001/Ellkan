// Autor: Athan Espinoza

//! Service de los links legales — nunca importa `axum`.

use uuid::Uuid;

use crate::audit::models::{AuditEventType, EventoAuditoria};
use crate::error::DomainError;
use crate::eventos::{DomainEvent, EmisorDeEventos};

use super::models::{TextosLegales, normalizar_link};
use super::repository::LegalLinksRepository;

pub struct LegalLinksService<'a, R> {
    pub repo: &'a R,
    pub eventos: EmisorDeEventos,
}

impl<R> LegalLinksService<'_, R>
where
    R: LegalLinksRepository,
{
    pub async fn obtener(&self) -> Result<TextosLegales, DomainError> {
        Ok(self.repo.obtener().await?)
    }

    pub async fn actualizar(
        &self,
        actor_id: Uuid,
        privacy_url: Option<&str>,
        terms_url: Option<&str>,
    ) -> Result<TextosLegales, DomainError> {
        let textos = TextosLegales {
            privacy_url: normalizar_link(privacy_url).map_err(|e| DomainError::ValidacionInvalida(format!("privacy_url: {e}")))?,
            terms_url: normalizar_link(terms_url).map_err(|e| DomainError::ValidacionInvalida(format!("terms_url: {e}")))?,
        };
        self.repo.actualizar(&textos).await?;
        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::LegalLinksUpdated, Some(actor_id)).con_metadata(serde_json::json!({
                "privacy_url": textos.privacy_url,
                "terms_url": textos.terms_url,
            })),
        ));
        Ok(textos)
    }
}
