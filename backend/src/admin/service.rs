// Autor: Athan Espinoza

//! Service de roles — nunca importa `axum`. La verificación de que el actor
//! ya es admin ocurre en el extractor `AdminUser` (capa de Controller), así
//! que este Service no vuelve a chequearlo: recibe la request ya autorizada.

use uuid::Uuid;

use crate::audit::models::{AuditEventType, EventoAuditoria};
use crate::error::DomainError;
use crate::eventos::{DomainEvent, EmisorDeEventos};

use super::models::Role;
use super::repository::RoleRepository;

pub struct RoleService<'a, R> {
    pub roles: &'a R,
    pub eventos: EmisorDeEventos,
}

impl<'a, R> RoleService<'a, R>
where
    R: RoleRepository,
{
    pub async fn listar(&self) -> Result<Vec<Role>, DomainError> {
        Ok(self.roles.listar().await?)
    }

    /// F-13: cambios en roles/permisos son configuración organizacional —
    /// se audita igual que cualquier otro endpoint mutante bajo `/admin/*`.
    pub async fn crear(
        &self,
        actor_id: Uuid,
        name: &str,
        permisos: Vec<String>,
    ) -> Result<Role, DomainError> {
        if name.trim().is_empty() {
            return Err(DomainError::ValidacionInvalida("name no puede estar vacío".into()));
        }
        let rol = self.roles.crear(name, &permisos).await.map_err(|e| match e {
            crate::error::RepoError::Conflict => DomainError::Conflict,
            otro => DomainError::Interno(otro),
        })?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::RoleCreated, Some(actor_id))
                .con_sujeto("role", rol.id)
                .con_metadata(serde_json::json!({ "name": rol.name })),
        ));

        Ok(rol)
    }

    pub async fn actualizar_permisos(
        &self,
        actor_id: Uuid,
        role_id: Uuid,
        permisos: Vec<String>,
    ) -> Result<Role, DomainError> {
        let rol = self
            .roles
            .reemplazar_permisos(role_id, &permisos)
            .await?
            .ok_or(DomainError::NotFound)?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::RolePermissionsUpdated, Some(actor_id))
                .con_sujeto("role", role_id)
                .con_metadata(serde_json::json!({ "permissions": permisos })),
        ));

        Ok(rol)
    }
}
