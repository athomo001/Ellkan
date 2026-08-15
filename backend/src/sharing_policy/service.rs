// Autor: Athan Espinoza

//! Service de política de compartir (2026-08-13) — nunca importa `axum`.

use uuid::Uuid;

use crate::audit::models::{AuditEventType, EventoAuditoria};
use crate::error::DomainError;
use crate::eventos::{DomainEvent, EmisorDeEventos};

use super::models::SharingPolicy;
use super::repository::SharingPolicyRepository;

pub struct SharingPolicyService<'a, P> {
    pub policy: &'a P,
    pub eventos: EmisorDeEventos,
}

impl<'a, P> SharingPolicyService<'a, P>
where
    P: SharingPolicyRepository,
{
    pub async fn obtener(&self) -> Result<SharingPolicy, DomainError> {
        Ok(self.policy.obtener().await?)
    }

    pub async fn actualizar(&self, actor_id: Uuid, nueva: SharingPolicy) -> Result<SharingPolicy, DomainError> {
        self.policy.actualizar(&nueva).await?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::SharingPolicyUpdated, Some(actor_id)).con_metadata(
                serde_json::json!({ "restrict_visibility_by_group": nueva.restrict_visibility_by_group }),
            ),
        ));

        Ok(nueva)
    }
}
