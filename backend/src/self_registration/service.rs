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

/// H-11 (auditoría 2026-08-12): un email con más de un `@` (ej.
/// `atacante@atacante.com@empresa-permitida.com`) hacía que `rsplit('@').next()`
/// devolviera el dominio permitido, mientras el string completo (no una
/// dirección RFC 5322 válida) seguía usándose como email real aguas abajo —
/// posible bypass del allowlist. No es un parser RFC 5322 completo (YAGNI:
/// esto sólo necesita cerrar el bypass, no validar cada caso límite de la
/// RFC) — exactamente un `@`, y ni la parte local ni el dominio vacíos.
fn formato_email_valido(email: &str) -> bool {
    match email.split_once('@') {
        Some((local, dominio)) => !local.is_empty() && !dominio.is_empty() && !dominio.contains('@'),
        None => false,
    }
}

/// Sólo la allowlist de dominios — el toggle `enabled` y el gate de
/// SMTP-configurado se resuelven en `auth::service::AuthService::registrar`
/// (dependen de si el registro es el bootstrap de la instancia, algo que
/// este módulo no necesita saber).
pub fn verificar_dominio_permitido(politica: &SelfRegistrationPolicy, email: &str) -> Result<(), DomainError> {
    if !formato_email_valido(email) {
        return Err(DomainError::ValidacionInvalida("formato de email inválido".into()));
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rechaza_email_con_doble_arroba_aunque_el_dominio_final_este_permitido() {
        let politica = SelfRegistrationPolicy { enabled: true, allowed_domains: vec!["empresa-permitida.com".into()] };
        let resultado = verificar_dominio_permitido(&politica, "atacante@atacante.com@empresa-permitida.com");
        assert!(resultado.is_err(), "un email con doble @ nunca debería pasar, sin importar qué dominio quede al final");
    }

    #[test]
    fn acepta_email_valido_con_dominio_permitido() {
        let politica = SelfRegistrationPolicy { enabled: true, allowed_domains: vec!["empresa-permitida.com".into()] };
        assert!(verificar_dominio_permitido(&politica, "alice@empresa-permitida.com").is_ok());
    }

    #[test]
    fn rechaza_email_sin_arroba() {
        let politica = SelfRegistrationPolicy { enabled: true, allowed_domains: vec![] };
        assert!(verificar_dominio_permitido(&politica, "no-es-un-email").is_err());
    }
}
