// Autor: Athan Espinoza

//! Service de roles — nunca importa `axum`. La verificación de que el actor
//! ya es admin ocurre en el extractor `AdminUser` (capa de Controller), así
//! que este Service no vuelve a chequearlo: recibe la request ya autorizada.

use uuid::Uuid;

use crate::error::DomainError;

use super::models::Role;
use super::repository::RoleRepository;

pub struct RoleService<'a, R> {
    pub roles: &'a R,
}

impl<'a, R> RoleService<'a, R>
where
    R: RoleRepository,
{
    pub async fn listar(&self) -> Result<Vec<Role>, DomainError> {
        Ok(self.roles.listar().await?)
    }

    pub async fn crear(&self, name: &str, permisos: Vec<String>) -> Result<Role, DomainError> {
        if name.trim().is_empty() {
            return Err(DomainError::ValidacionInvalida("name no puede estar vacío".into()));
        }
        self.roles.crear(name, &permisos).await.map_err(|e| match e {
            crate::error::RepoError::Conflict => DomainError::Conflict,
            otro => DomainError::Interno(otro),
        })
    }

    pub async fn actualizar_permisos(
        &self,
        role_id: Uuid,
        permisos: Vec<String>,
    ) -> Result<Role, DomainError> {
        self.roles
            .reemplazar_permisos(role_id, &permisos)
            .await?
            .ok_or(DomainError::NotFound)
    }
}
