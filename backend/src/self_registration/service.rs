// Autor: Athan Espinoza

//! Service de política de auto-registro (F-24) — nunca importa `axum`.

use uuid::Uuid;

use crate::audit::models::{AuditEventType, EventoAuditoria};
use crate::error::DomainError;
use crate::eventos::{DomainEvent, EmisorDeEventos};

use super::models::SelfRegistrationPolicy;
use super::repository::SelfRegistrationPolicyRepository;

pub struct SelfRegistrationPolicyService<'a, P> {
    pub policy: &'a P,
    pub eventos: EmisorDeEventos,
}

impl<'a, P> SelfRegistrationPolicyService<'a, P>
where
    P: SelfRegistrationPolicyRepository,
{
    pub async fn obtener(&self) -> Result<SelfRegistrationPolicy, DomainError> {
        Ok(self.policy.obtener().await?)
    }

    pub async fn actualizar(
        &self,
        actor_id: Uuid,
        nueva: SelfRegistrationPolicy,
    ) -> Result<SelfRegistrationPolicy, DomainError> {
        self.policy.actualizar(&nueva).await?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::SelfRegistrationPolicyUpdated, Some(actor_id)).con_metadata(
                serde_json::json!({
                    "enabled": nueva.enabled,
                    "allowed_domains": nueva.allowed_domains,
                }),
            ),
        ));

        Ok(nueva)
    }
}

/// Sólo la allowlist de dominios — el toggle `enabled` y el gate de
/// SMTP-configurado se resuelven en `auth::service::AuthService::registrar`
/// (dependen de si el registro es el bootstrap de la instancia, algo que
/// este módulo no necesita saber).
pub fn verificar_dominio_permitido(politica: &SelfRegistrationPolicy, email: &str) -> Result<(), DomainError> {
    if politica.allowed_domains.is_empty() {
        return Ok(());
    }
    let dominio = email.rsplit('@').next().unwrap_or("").to_lowercase();
    let permitido = politica.allowed_domains.iter().any(|d| d.to_lowercase() == dominio);
    if !permitido {
        return Err(DomainError::ValidacionInvalida("dominio de email no permitido para auto-registro".into()));
    }
    Ok(())
}
