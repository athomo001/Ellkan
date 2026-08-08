// Autor: Athan Espinoza

//! Service de recursos — nunca importa `axum`. El servidor nunca ve
//! `metadata`/secreto en claro ni una DEK sin sellar: sólo mueve bytes ya
//! cifrados client-side (F-05, F-06, F-07).

use uuid::Uuid;

use crate::audit::models::{AuditEventType, EventoAuditoria};
use crate::error::DomainError;
use crate::eventos::{DomainEvent, EmisorDeEventos};

use super::models::{Destinatario, EnvelopeInput, NivelPermiso, Resource, SecretEnvelope};
use super::repository::{
    PermissionRepository, ResourceRepository, ResourceTypeRepository, SecretEnvelopeRepository,
};

pub struct ResourceService<'a, R, E, P, T> {
    pub recursos: &'a R,
    pub envolturas: &'a E,
    pub permisos: &'a P,
    pub tipos_recurso: &'a T,
    pub eventos: EmisorDeEventos,
}

#[allow(clippy::too_many_arguments)]
impl<'a, R, E, P, T> ResourceService<'a, R, E, P, T>
where
    R: ResourceRepository,
    E: SecretEnvelopeRepository,
    P: PermissionRepository,
    T: ResourceTypeRepository,
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
        metadata_key_id: Option<Uuid>,
    ) -> Result<Resource, DomainError> {
        let recurso = self
            .recursos
            .crear(id, resource_type_id, metadata_ciphertext, metadata_nonce, owner_id, metadata_key_id)
            .await?;

        self.envolturas
            .insertar(recurso.id, owner_id, sealed_dek, secret_ciphertext, secret_nonce)
            .await?;

        self.permisos
            .otorgar(recurso.id, owner_id, NivelPermiso::Owner.as_db_str())
            .await?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::ResourceCreated, Some(owner_id))
                .con_sujeto("resource", recurso.id),
        ));

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

        // F-06 completo: sólo un recurso cifrado con la metadata key
        // compartida puede compartirse — uno con metadata personal
        // (`user_key`) fallaría en que el destinatario ni siquiera pueda
        // descifrar el nombre/URI, así que se rechaza acá, explícito.
        let recurso = self.recursos.buscar(resource_id).await?.ok_or(DomainError::NotFound)?;
        if recurso.metadata_key_type != "shared_key" {
            return Err(DomainError::MetadataPersonalNoCompartible);
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

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::PermissionGranted, Some(owner_id))
                .con_sujeto("resource", resource_id)
                .con_metadata(serde_json::json!({
                    "recipient_user_id": recipient_id,
                    "level": nivel.as_db_str(),
                })),
        ));

        Ok(())
    }

    /// F-33: el cliente descifró la metadata con la clave saliente (via su
    /// propio `metadata_key_envelopes`) y la re-envuelve para la entrante —
    /// el servidor sólo mueve bytes opacos, igual criterio que el resto de
    /// este Service. Exige `update`+ (misma autoridad que editar el
    /// recurso), no `owner` — re-envolver metadata durante una rotación no
    /// es una decisión de a quién pertenece el recurso.
    pub async fn rekey_metadata(
        &self,
        resource_id: Uuid,
        actor_id: Uuid,
        expected_current_metadata_key_id: Uuid,
        new_metadata_key_id: Uuid,
        metadata_ciphertext: &[u8],
        metadata_nonce: &[u8],
    ) -> Result<(), DomainError> {
        if !self
            .permisos
            .tiene_permiso(resource_id, actor_id, NivelPermiso::Update.as_db_str())
            .await?
        {
            return Err(DomainError::PermissionDenied);
        }

        let aplicado = self
            .recursos
            .rekey_metadata(
                resource_id,
                expected_current_metadata_key_id,
                new_metadata_key_id,
                metadata_ciphertext,
                metadata_nonce,
            )
            .await?;

        if !aplicado {
            return Err(DomainError::Conflict);
        }
        Ok(())
    }

    /// `GET /resources/{id}/recipients` (F-07) — mismo permiso mínimo que
    /// leer el recurso: hace falta antes de armar el `PUT`, para saber a
    /// quién re-sellar la DEK nueva.
    pub async fn listar_destinatarios(&self, resource_id: Uuid, user_id: Uuid) -> Result<Vec<Destinatario>, DomainError> {
        if !self
            .permisos
            .tiene_permiso(resource_id, user_id, NivelPermiso::Read.as_db_str())
            .await?
        {
            return Err(DomainError::PermissionDenied);
        }
        Ok(self.recursos.listar_destinatarios(resource_id).await?)
    }

    /// `PUT /resources/{id}` (F-07) — edita metadata + re-sella el secreto
    /// para todos los destinatarios actuales (el cliente ya hizo el trabajo
    /// criptográfico, acá sólo se autoriza y se aplica de forma atómica).
    /// Exige `update`+ (misma autoridad que `rekey_metadata`), no `owner` —
    /// editar contenido no es una decisión de a quién pertenece el recurso.
    #[allow(clippy::too_many_arguments)]
    pub async fn editar(
        &self,
        resource_id: Uuid,
        actor_id: Uuid,
        expected_updated_at: time::OffsetDateTime,
        metadata_ciphertext: &[u8],
        metadata_nonce: &[u8],
        envelopes: Vec<EnvelopeInput>,
    ) -> Result<Resource, DomainError> {
        if !self
            .permisos
            .tiene_permiso(resource_id, actor_id, NivelPermiso::Update.as_db_str())
            .await?
        {
            return Err(DomainError::PermissionDenied);
        }

        let resultado = self
            .recursos
            .actualizar(resource_id, expected_updated_at, metadata_ciphertext, metadata_nonce, &envelopes)
            .await?;
        let recurso = resultado.ok_or(DomainError::Conflict)?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::ResourceUpdated, Some(actor_id))
                .con_sujeto("resource", resource_id)
                .con_metadata(serde_json::json!({ "destinatarios": envelopes.len() })),
        ));

        Ok(recurso)
    }

    /// `GET /resources/{id}/totp` (F-08) — sólo metadata de configuración,
    /// nunca el código generado (eso lo calcula el cliente tras descifrar
    /// vía `/resources/{id}/secret`). Deriva de si el `resource_type`
    /// declara `totp_secret` en `secret`, nunca inspecciona contenido
    /// cifrado.
    pub async fn tiene_totp(&self, resource_id: Uuid, user_id: Uuid) -> Result<bool, DomainError> {
        if !self
            .permisos
            .tiene_permiso(resource_id, user_id, NivelPermiso::Read.as_db_str())
            .await?
        {
            return Err(DomainError::PermissionDenied);
        }

        let recurso = self.recursos.buscar(resource_id).await?.ok_or(DomainError::NotFound)?;
        let schema = self
            .tipos_recurso
            .json_schema_por_id(recurso.resource_type_id)
            .await?
            .ok_or(DomainError::NotFound)?;

        let declara_totp = schema["secret"]
            .as_array()
            .is_some_and(|campos| campos.iter().any(|c| c == "totp_secret"));
        Ok(declara_totp)
    }
}
