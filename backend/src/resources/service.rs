// Autor: Athan Espinoza

//! Service de recursos — nunca importa `axum`. El servidor nunca ve
//! `metadata`/secreto en claro ni una DEK sin sellar: sólo mueve bytes ya
//! cifrados client-side (F-05, F-06, F-07).

use uuid::Uuid;

use crate::error::DomainError;

use super::models::{NivelPermiso, Resource, SecretEnvelope};
use super::repository::{PermissionRepository, ResourceRepository, SecretEnvelopeRepository};

pub struct ResourceService<'a, R, E, P> {
    pub recursos: &'a R,
    pub envolturas: &'a E,
    pub permisos: &'a P,
}

#[allow(clippy::too_many_arguments)]
impl<'a, R, E, P> ResourceService<'a, R, E, P>
where
    R: ResourceRepository,
    E: SecretEnvelopeRepository,
    P: PermissionRepository,
{
    pub async fn crear(
        &self,
        id: Uuid,
        resource_type_id: Uuid,
        metadata_ciphertext: &[u8],
        metadata_nonce: &[u8],
        owner_id: Uuid,
        sealed_dek: &[u8],
        secret_ciphertext: &[u8],
        secret_nonce: &[u8],
    ) -> Result<Resource, DomainError> {
        let recurso = self
            .recursos
            .crear(id, resource_type_id, metadata_ciphertext, metadata_nonce, owner_id)
            .await?;

        self.envolturas
            .insertar(recurso.id, owner_id, sealed_dek, secret_ciphertext, secret_nonce)
            .await?;

        self.permisos
            .otorgar(recurso.id, owner_id, NivelPermiso::Owner.as_db_str())
            .await?;

        Ok(recurso)
    }

    pub async fn listar_visibles(&self, user_id: Uuid) -> Result<Vec<Resource>, DomainError> {
        Ok(self.recursos.listar_visibles_por(user_id).await?)
    }

    /// `GET /resources/{id}`.
    pub async fn obtener(&self, resource_id: Uuid, user_id: Uuid) -> Result<Resource, DomainError> {
        if !self
            .permisos
            .tiene_permiso(resource_id, user_id, NivelPermiso::Read.as_db_str())
            .await?
        {
            return Err(DomainError::PermissionDenied);
        }

        self.recursos.buscar(resource_id).await?.ok_or(DomainError::NotFound)
    }

    /// Devuelve el envelope del usuario autenticado únicamente — para
    /// `GET /resources/{id}/secret`.
    pub async fn obtener_secreto(
        &self,
        resource_id: Uuid,
        user_id: Uuid,
    ) -> Result<SecretEnvelope, DomainError> {
        if !self
            .permisos
            .tiene_permiso(resource_id, user_id, NivelPermiso::Read.as_db_str())
            .await?
        {
            return Err(DomainError::PermissionDenied);
        }

        self.envolturas
            .buscar(resource_id, user_id)
            .await?
            .ok_or(DomainError::NotFound)
    }

    /// F-05, F-11 básico: comparte con un usuario concreto, sin grupos
    /// todavía. El cliente ya selló `sealed_dek` para la clave pública X25519
    /// del destinatario — el servidor sólo autoriza y guarda bytes opacos.
    pub async fn compartir(
        &self,
        resource_id: Uuid,
        owner_id: Uuid,
        recipient_id: Uuid,
        sealed_dek: &[u8],
        secret_ciphertext: &[u8],
        secret_nonce: &[u8],
        nivel: NivelPermiso,
    ) -> Result<(), DomainError> {
        if !self
            .permisos
            .tiene_permiso(resource_id, owner_id, NivelPermiso::Owner.as_db_str())
            .await?
        {
            return Err(DomainError::PermissionDenied);
        }

        self.envolturas
            .insertar(resource_id, recipient_id, sealed_dek, secret_ciphertext, secret_nonce)
            .await
            .map_err(|e| match e {
                crate::error::RepoError::Conflict => DomainError::Conflict,
                otro => DomainError::Interno(otro),
            })?;

        self.permisos
            .otorgar(resource_id, recipient_id, nivel.as_db_str())
            .await?;

        Ok(())
    }
}
