// Autor: Athan Espinoza

//! Service de política de password/passphrase (F-15) — nunca importa
//! `axum`. La validación de entropía/longitud de una passphrase concreta
//! corre client-side (`zxcvbn`, la passphrase en claro nunca viaja al
//! servidor) — este Service sólo guarda y sirve los parámetros de la
//! política, con el único piso que sí se exige server-side: nunca por
//! debajo de 12 caracteres, el mismo mínimo que el propio default de
//! fábrica (F-15).

use uuid::Uuid;

use crate::audit::models::{AuditEventType, EventoAuditoria};
use crate::error::DomainError;
use crate::eventos::{DomainEvent, EmisorDeEventos};

use super::models::PasswordPolicy;
use super::repository::PasswordPolicyRepository;

const PISO_MIN_PASSPHRASE_LENGTH: i32 = 12;

pub struct PasswordPolicyService<'a, P> {
    pub policy: &'a P,
    pub eventos: EmisorDeEventos,
}

impl<'a, P> PasswordPolicyService<'a, P>
where
    P: PasswordPolicyRepository,
{
    pub async fn obtener(&self) -> Result<PasswordPolicy, DomainError> {
        Ok(self.policy.obtener().await?)
    }

    pub async fn actualizar(
        &self,
        actor_id: Uuid,
        nueva: PasswordPolicy,
    ) -> Result<PasswordPolicy, DomainError> {
        if nueva.min_passphrase_length < PISO_MIN_PASSPHRASE_LENGTH {
            return Err(DomainError::ValidacionInvalida(format!(
                "min_passphrase_length no puede bajar de {PISO_MIN_PASSPHRASE_LENGTH}"
            )));
        }
        if nueva.min_passphrase_entropy_bits < 0 {
            return Err(DomainError::ValidacionInvalida(
                "min_passphrase_entropy_bits no puede ser negativo".into(),
            ));
        }
        if nueva.generator_default_length < 1 {
            return Err(DomainError::ValidacionInvalida(
                "generator_default_length debe ser al menos 1".into(),
            ));
        }
        if nueva.passphrase_rotation_days.is_some_and(|d| d <= 0) {
            return Err(DomainError::ValidacionInvalida(
                "passphrase_rotation_days debe ser positivo si se fija (null = sin rotación forzada)".into(),
            ));
        }

        self.policy.actualizar(&nueva).await?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::PasswordPolicyUpdated, Some(actor_id)).con_metadata(
                serde_json::json!({
                    "min_passphrase_length": nueva.min_passphrase_length,
                    "min_passphrase_entropy_bits": nueva.min_passphrase_entropy_bits,
                    "passphrase_rotation_days": nueva.passphrase_rotation_days,
                }),
            ),
        ));

        Ok(nueva)
    }
}
