// Autor: Athan Espinoza

//! Service de retención/purga (F-40) — nunca importa `axum`.

use uuid::Uuid;

use crate::audit::models::{AuditEventType, EventoAuditoria};
use crate::error::DomainError;
use crate::eventos::{DomainEvent, EmisorDeEventos};

use super::models::{ResultadoPurga, RetentionPolicy};
use super::repository::{PurgeRepository, RetentionPolicyRepository};

pub struct RetentionService<'a, P, X> {
    pub policy: &'a P,
    pub purga: &'a X,
    pub eventos: EmisorDeEventos,
}

impl<'a, P, X> RetentionService<'a, P, X>
where
    P: RetentionPolicyRepository,
    X: PurgeRepository,
{
    pub async fn politica(&self) -> Result<RetentionPolicy, DomainError> {
        Ok(self.policy.obtener().await?)
    }

    pub async fn actualizar_politica(
        &self,
        actor_id: Uuid,
        data_retention_days: i32,
        audit_log_retention_days: i32,
    ) -> Result<RetentionPolicy, DomainError> {
        if data_retention_days < 1 {
            return Err(DomainError::ValidacionInvalida("data_retention_days debe ser al menos 1".into()));
        }
        if audit_log_retention_days < 1 {
            return Err(DomainError::ValidacionInvalida("audit_log_retention_days debe ser al menos 1".into()));
        }

        let nueva = RetentionPolicy { data_retention_days, audit_log_retention_days };
        self.policy.actualizar(&nueva).await?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::RetentionPolicyUpdated, Some(actor_id)).con_metadata(
                serde_json::json!({
                    "data_retention_days": nueva.data_retention_days,
                    "audit_log_retention_days": nueva.audit_log_retention_days,
                }),
            ),
        ));

        Ok(nueva)
    }

    pub async fn correr_purga(&self) -> Result<ResultadoPurga, DomainError> {
        let politica = self.policy.obtener().await?;
        let resultado =
            self.purga.purgar(politica.data_retention_days, politica.audit_log_retention_days).await?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::RetentionPurgeRan, None).con_metadata(serde_json::json!({
                "resources": resultado.resources,
                "folders": resultado.folders,
                "tags": resultado.tags,
                "groups": resultado.groups,
                "user_totp_credentials": resultado.user_totp_credentials,
                "audit_log_entries": resultado.audit_log_entries,
            })),
        ));

        Ok(resultado)
    }
}
