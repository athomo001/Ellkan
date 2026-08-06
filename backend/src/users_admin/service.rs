// Autor: Athan Espinoza

//! Service de administración de usuarios (F-40) — nunca importa `axum`.

use uuid::Uuid;

use crate::audit::models::{AuditEventType, EventoAuditoria};
use crate::error::DomainError;
use crate::eventos::{DomainEvent, EmisorDeEventos};

use super::models::{Bloqueos, ResultadoPurgaUsuario, ResumenUsuario, Transferencia};
use super::repository::UserPurgeRepository;

pub struct UsersAdminService<'a, R> {
    pub repo: &'a R,
    pub eventos: EmisorDeEventos,
}

impl<'a, R> UsersAdminService<'a, R>
where
    R: UserPurgeRepository,
{
    pub async fn obtener(&self, user_id: Uuid) -> Result<ResumenUsuario, DomainError> {
        self.repo.obtener_resumen(user_id).await?.ok_or(DomainError::NotFound)
    }

    pub async fn dry_run_purga(&self, user_id: Uuid) -> Result<Bloqueos, DomainError> {
        if !self.repo.activo_y_existe(user_id).await? {
            return Err(DomainError::NotFound);
        }
        Ok(self.repo.calcular_bloqueos(user_id).await?)
    }

    /// `POST /admin/users/{id}/purge` — irreversible, auditado. La
    /// transacción entera falla si la transferencia no cubre el 100% de lo
    /// bloqueante (`RepoError::Conflict` desde el repository).
    pub async fn purgar(
        &self,
        actor_id: Uuid,
        user_id: Uuid,
        transferencia: Transferencia,
    ) -> Result<ResultadoPurgaUsuario, DomainError> {
        let resultado = self.repo.purgar(user_id, &transferencia).await.map_err(|e| match e {
            crate::error::RepoError::Conflict => DomainError::Conflict,
            otro => DomainError::Interno(otro),
        })?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::UserPurged, Some(actor_id))
                .con_sujeto("user", user_id)
                .con_metadata(serde_json::json!({
                    "resources_huerfanos_eliminados": resultado.resources_huerfanos_eliminados,
                    "owners_transferidos": transferencia.owners.len(),
                    "managers_transferidos": transferencia.managers.len(),
                })),
        ));

        Ok(resultado)
    }

    pub async fn desactivar(&self, actor_id: Uuid, user_id: Uuid) -> Result<(), DomainError> {
        if !self.repo.desactivar(user_id).await? {
            return Err(DomainError::NotFound);
        }
        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::UserDeactivated, Some(actor_id)).con_sujeto("user", user_id),
        ));
        Ok(())
    }

    pub async fn activar(&self, actor_id: Uuid, user_id: Uuid) -> Result<(), DomainError> {
        if !self.repo.activar(user_id).await? {
            return Err(DomainError::NotFound);
        }
        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::UserActivated, Some(actor_id)).con_sujeto("user", user_id),
        ));
        Ok(())
    }
}
