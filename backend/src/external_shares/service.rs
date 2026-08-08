// Autor: Athan Espinoza

//! Service de External Secure Share (F-26) — nunca importa `axum`. El
//! servidor es enteramente ciego al contenido: recibe y devuelve bytes
//! opacos, la única lógica de dominio acá es *cuándo* un share sigue
//! siendo accesible (política, expiración, cupo de vistas), nunca qué hay
//! adentro.

use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::audit::models::{AuditEventType, EventoAuditoria};
use crate::error::DomainError;
use crate::eventos::{DomainEvent, EmisorDeEventos};

use super::models::{ExternalSharePolicy, FilaExternalShare, NuevoExternalShare, ResultadoAcceso};
use super::repository::{ExternalSharePolicyRepository, ExternalShareRepository};

pub struct ExternalShareService<'a, S, P> {
    pub shares: &'a S,
    pub policy: &'a P,
    pub eventos: EmisorDeEventos,
}

/// Contenido devuelto al Controller tras un acceso exitoso — nunca incluye
/// la clave de descifrado, que jamás llegó al servidor.
pub struct ContenidoAcceso {
    pub ciphertext: Vec<u8>,
    pub password_protected: bool,
    pub password_salt: Option<Vec<u8>>,
}

impl<'a, S, P> ExternalShareService<'a, S, P>
where
    S: ExternalShareRepository,
    P: ExternalSharePolicyRepository,
{
    pub async fn crear(
        &self,
        actor_id: Uuid,
        ciphertext: Vec<u8>,
        password_protected: bool,
        password_salt: Option<Vec<u8>>,
        max_views: Option<i32>,
        expires_in_hours: i32,
    ) -> Result<FilaExternalShare, DomainError> {
        let politica = self.policy.obtener().await?;
        if !politica.enabled {
            return Err(DomainError::PermissionDenied);
        }
        if politica.require_password && !password_protected {
            return Err(DomainError::ValidacionInvalida(
                "la política organizacional exige la capa de passphrase para external shares".into(),
            ));
        }

        let max_views = max_views.unwrap_or(1);
        if max_views < 1 {
            return Err(DomainError::ValidacionInvalida("max_views debe ser al menos 1".into()));
        }
        if expires_in_hours < 1 {
            return Err(DomainError::ValidacionInvalida("expires_in_hours debe ser al menos 1".into()));
        }
        if expires_in_hours > politica.max_expiration_hours {
            return Err(DomainError::ValidacionInvalida(format!(
                "expires_in_hours no puede superar el máximo de la política ({} horas)",
                politica.max_expiration_hours
            )));
        }
        if password_protected && password_salt.is_none() {
            return Err(DomainError::ValidacionInvalida(
                "password_salt_b64 es obligatorio cuando password_protected es true".into(),
            ));
        }

        let expires_at = OffsetDateTime::now_utc() + Duration::hours(i64::from(expires_in_hours));
        let nuevo = NuevoExternalShare { created_by: actor_id, ciphertext, password_protected, password_salt, max_views, expires_at };
        let fila = self.shares.crear(&nuevo).await?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::ExternalShareCreated, Some(actor_id))
                .con_sujeto("external_share", fila.id)
                .con_metadata(serde_json::json!({
                    "max_views": fila.max_views,
                    "expires_in_hours": expires_in_hours,
                    "password_protected": password_protected,
                })),
        ));

        Ok(fila)
    }

    pub async fn revocar(&self, actor_id: Uuid, id: Uuid) -> Result<(), DomainError> {
        let fila = self.shares.obtener(id).await?.ok_or(DomainError::NotFound)?;
        if fila.created_by != actor_id {
            return Err(DomainError::PermissionDenied);
        }
        if fila.revoked_at.is_some() || fila.burned_at.is_some() {
            return Err(DomainError::Conflict);
        }

        let revocado = self.shares.revocar(id).await?;
        if !revocado {
            return Err(DomainError::Conflict);
        }

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::ExternalShareRevoked, Some(actor_id))
                .con_sujeto("external_share", id),
        ));

        Ok(())
    }

    /// Anti-enumeración, mismo criterio que el resto de la API: no existe,
    /// ya se quemó, ya se revocó y ya expiró se colapsan todos al mismo
    /// `NotFound` — no hay forma de distinguirlos desde afuera.
    pub async fn acceder(&self, id: Uuid) -> Result<ContenidoAcceso, DomainError> {
        match self.shares.acceder(id).await? {
            ResultadoAcceso::Ok { ciphertext, password_protected, password_salt, quemado_ahora } => {
                let _ = self.eventos.send(DomainEvent::Auditoria(
                    EventoAuditoria::nuevo(AuditEventType::ExternalShareAccessed, None)
                        .con_sujeto("external_share", id)
                        .con_metadata(serde_json::json!({ "quemado_ahora": quemado_ahora })),
                ));
                if quemado_ahora {
                    let _ = self.eventos.send(DomainEvent::Auditoria(
                        EventoAuditoria::nuevo(AuditEventType::ExternalShareBurned, None)
                            .con_sujeto("external_share", id)
                            .con_metadata(serde_json::json!({ "reason": "max_views_reached" })),
                    ));
                }
                Ok(ContenidoAcceso { ciphertext, password_protected, password_salt })
            }
            ResultadoAcceso::Expirado => {
                let _ = self.eventos.send(DomainEvent::Auditoria(
                    EventoAuditoria::nuevo(AuditEventType::ExternalShareBurned, None)
                        .con_sujeto("external_share", id)
                        .con_metadata(serde_json::json!({ "reason": "expired" })),
                ));
                Err(DomainError::NotFound)
            }
            ResultadoAcceso::NoEncontrado | ResultadoAcceso::Revocado | ResultadoAcceso::Quemado => {
                Err(DomainError::NotFound)
            }
        }
    }

    pub async fn politica(&self) -> Result<ExternalSharePolicy, DomainError> {
        Ok(self.policy.obtener().await?)
    }

    pub async fn actualizar_politica(
        &self,
        actor_id: Uuid,
        enabled: bool,
        max_expiration_hours: i32,
        require_password: bool,
    ) -> Result<ExternalSharePolicy, DomainError> {
        if max_expiration_hours < 1 {
            return Err(DomainError::ValidacionInvalida("max_expiration_hours debe ser al menos 1".into()));
        }

        let nueva = ExternalSharePolicy { enabled, max_expiration_hours, require_password };
        self.policy.actualizar(&nueva).await?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::ExternalSharePolicyUpdated, Some(actor_id)).con_metadata(
                serde_json::json!({
                    "enabled": nueva.enabled,
                    "max_expiration_hours": nueva.max_expiration_hours,
                    "require_password": nueva.require_password,
                }),
            ),
        ));

        Ok(nueva)
    }
}
