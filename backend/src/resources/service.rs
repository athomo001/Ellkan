// Autor: Athan Espinoza

//! Service de recursos — nunca importa `axum`. El servidor nunca ve
//! `metadata`/secreto en claro ni una DEK sin sellar: sólo mueve bytes ya
//! cifrados client-side (F-05, F-06, F-07).

use uuid::Uuid;

use crate::audit::models::{AuditEventType, EventoAuditoria};
use crate::error::DomainError;
use crate::eventos::{DomainEvent, EmisorDeEventos};

use super::models::{Destinatario, EnvelopeInput, NivelPermiso, PermisoGrantee, Resource, SecretEnvelope};
use super::repository::{
    PermissionRepository, ResourceRepository, ResourceTypeRepository, SecretEnvelopeRepository,
};

/// Ítem ya decodificado (base64 aplicado, `level` resuelto) para
/// `ResourceService::compartir_lote` — evita un tuple de 6 elementos.
pub struct ItemCompartirLote {
    pub resource_id: Uuid,
    pub recipient_id: Uuid,
    pub sealed_dek: Vec<u8>,
    pub secret_ciphertext: Vec<u8>,
    pub secret_nonce: Vec<u8>,
    pub nivel: NivelPermiso,
}

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
            .otorgar("resource", recurso.id, owner_id, NivelPermiso::Owner.as_db_str())
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
            .tiene_permiso("resource", resource_id, user_id, NivelPermiso::Read.as_db_str())
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
            .tiene_permiso("resource", resource_id, user_id, NivelPermiso::Read.as_db_str())
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
            .tiene_permiso("resource", resource_id, owner_id, NivelPermiso::Owner.as_db_str())
            .await?
        {
            return Err(DomainError::PermissionDenied);
        }

        // F-06/hallazgo real 2026-08-11: esto rechazaba compartir un recurso
        // `user_key` asumiendo que el destinatario no podría descifrar la
        // metadata — falso con el mecanismo de envelopes actual: la DEK es
        // la MISMA para metadata y secreto en `user_key` (ver comentario de
        // cabecera del módulo), y `compartirRecursoConDestinatario` ya
        // re-sella esa DEK exacta para el destinatario nuevo — igual que
        // `editarRecurso` ya re-sella metadata+secreto para todos los
        // destinatarios actuales de un `user_key` en cada edición. No hay
        // ninguna limitación criptográfica real; `secret_envelopes` soporta
        // múltiples filas por recurso desde Fase 0 (`unique(resource_id,
        // user_id)`). Se mantiene el `buscar` sólo para el 404 explícito.
        self.recursos.buscar(resource_id).await?.ok_or(DomainError::NotFound)?;

        self.envolturas
            .insertar(resource_id, recipient_id, sealed_dek, secret_ciphertext, secret_nonce)
            .await
            .map_err(|e| match e {
                // Hallazgo real de uso 2026-08-11: `DomainError::Conflict`
                // generico ("conflicto de estado") no le decía nada al
                // usuario sobre POR QUÉ falló — acá el único conflicto
                // posible es `unique(resource_id, user_id)` de
                // `secret_envelopes`, o sea que ese destinatario ya tiene
                // acceso. Mensaje explícito en vez del genérico.
                crate::error::RepoError::Conflict => {
                    DomainError::ValidacionInvalida("esta persona ya tiene acceso a este recurso".into())
                }
                otro => DomainError::Interno(otro),
            })?;

        self.permisos
            .otorgar("resource", resource_id, recipient_id, nivel.as_db_str())
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

    /// Módulo 3 (compartir en lote) — loop de `compartir()` ítem por ítem,
    /// sin transacción envolvente: el share individual tampoco es atómico
    /// entre el insert de envelope y el otorgamiento de permiso, así que
    /// prometer atomicidad recién acá sería inconsistente con lo que ya
    /// existe. Un ítem inválido no aborta el resto — mismo criterio
    /// tolerante-a-fallos-parciales que la carga CSV de grupos (Bloque C).
    pub async fn compartir_lote(&self, owner_id: Uuid, items: Vec<ItemCompartirLote>) -> Vec<(Uuid, Uuid, Option<String>)> {
        let mut resultados = Vec::with_capacity(items.len());
        for item in items {
            let error = self
                .compartir(
                    item.resource_id,
                    owner_id,
                    item.recipient_id,
                    &item.sealed_dek,
                    &item.secret_ciphertext,
                    &item.secret_nonce,
                    item.nivel,
                )
                .await
                .err()
                .map(|e| e.to_string());
            resultados.push((item.resource_id, item.recipient_id, error));
        }
        resultados
    }

    /// `GET /resources/{id}/permissions` — hallazgo real de uso: no había
    /// forma de VER con quién estaba compartido un recurso ni en qué nivel,
    /// más allá de agregar un destinatario nuevo a ciegas. Owner-only, mismo
    /// criterio que "sólo un Owner puede tocar quién tiene acceso" (F-11).
    pub async fn listar_permisos(&self, resource_id: Uuid, actor_id: Uuid) -> Result<Vec<PermisoGrantee>, DomainError> {
        if !self.permisos.tiene_permiso("resource", resource_id, actor_id, NivelPermiso::Owner.as_db_str()).await? {
            return Err(DomainError::PermissionDenied);
        }
        Ok(self.permisos.listar("resource", resource_id).await?)
    }

    /// `PUT /resources/{id}/permissions/{grantee_type}/{grantee_id}` — sólo
    /// cambia el nivel, nunca la crypto (la DEK ya sellada para ese
    /// destinatario no depende del nivel de permiso). Si el cambio bajaría
    /// al único Owner actual, falla explícito — mismo criterio que F-11 ya
    /// documenta para el lote atómico.
    pub async fn cambiar_nivel(
        &self,
        resource_id: Uuid,
        actor_id: Uuid,
        grantee_type: &str,
        grantee_id: Uuid,
        nuevo_nivel: NivelPermiso,
    ) -> Result<(), DomainError> {
        if !self.permisos.tiene_permiso("resource", resource_id, actor_id, NivelPermiso::Owner.as_db_str()).await? {
            return Err(DomainError::PermissionDenied);
        }
        if nuevo_nivel != NivelPermiso::Owner
            && !self.permisos.existe_otro_owner("resource", resource_id, grantee_type, grantee_id).await?
        {
            return Err(DomainError::ValidacionInvalida("el recurso se quedaría sin ningún Owner".into()));
        }

        // Sólo usuarios por ahora (compartir con grupos sigue siendo el
        // mecanismo aparte de `GroupService`, F-12) — `otorgar` ya es upsert.
        if grantee_type != "user" {
            return Err(DomainError::ValidacionInvalida("cambiar nivel sólo soportado para destinatarios usuario".into()));
        }
        self.permisos.otorgar("resource", resource_id, grantee_id, nuevo_nivel.as_db_str()).await?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::PermissionGranted, Some(actor_id))
                .con_sujeto("resource", resource_id)
                .con_metadata(serde_json::json!({ "grantee_type": grantee_type, "grantee_id": grantee_id, "level": nuevo_nivel.as_db_str() })),
        ));
        Ok(())
    }

    /// `DELETE /resources/{id}/permissions/{grantee_type}/{grantee_id}` —
    /// revoca acceso; el `secret_envelope` que le quede al destinatario
    /// borrado queda huérfano (inalcanzable, `obtener_secreto` chequea
    /// `permissions` primero) — no hace falta borrarlo aparte para que deje
    /// de tener efecto.
    pub async fn revocar_permiso(
        &self,
        resource_id: Uuid,
        actor_id: Uuid,
        grantee_type: &str,
        grantee_id: Uuid,
    ) -> Result<(), DomainError> {
        if !self.permisos.tiene_permiso("resource", resource_id, actor_id, NivelPermiso::Owner.as_db_str()).await? {
            return Err(DomainError::PermissionDenied);
        }
        if !self.permisos.existe_otro_owner("resource", resource_id, grantee_type, grantee_id).await? {
            return Err(DomainError::ValidacionInvalida("el recurso se quedaría sin ningún Owner".into()));
        }
        self.permisos.revocar("resource", resource_id, grantee_type, grantee_id).await?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::PermissionGranted, Some(actor_id))
                .con_sujeto("resource", resource_id)
                .con_metadata(serde_json::json!({ "grantee_type": grantee_type, "grantee_id": grantee_id, "revoked": true })),
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
            .tiene_permiso("resource", resource_id, actor_id, NivelPermiso::Update.as_db_str())
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
            .tiene_permiso("resource", resource_id, user_id, NivelPermiso::Read.as_db_str())
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
            .tiene_permiso("resource", resource_id, actor_id, NivelPermiso::Update.as_db_str())
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
            .tiene_permiso("resource", resource_id, user_id, NivelPermiso::Read.as_db_str())
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
