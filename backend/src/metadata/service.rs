// Autor: Athan Espinoza

//! Service de metadata keys — nunca importa `axum`. La autorización de admin
//! ya la resuelve el extractor `AdminUser` en el Controller: a diferencia de
//! tags (F-10), acá no existe ningún camino no-admin legítimo, así que no
//! hace falta re-verificar el rol acá.

use uuid::Uuid;

use crate::audit::models::{AuditEventType, EventoAuditoria};
use crate::error::DomainError;
use crate::eventos::{DomainEvent, EmisorDeEventos};

use super::models::MetadataKey;
use super::repository::{MetadataKeyEnvelopeRepository, MetadataKeyRepository};

pub struct MetadataKeyService<'a, K, E> {
    pub claves: &'a K,
    pub envelopes: &'a E,
    pub eventos: EmisorDeEventos,
}

/// Snapshot de progreso — `GET /admin/metadata-keys/rotation-status`.
#[derive(Debug, Clone)]
pub struct EstadoRotacion {
    pub activa: bool,
    pub saliente_id: Option<Uuid>,
    pub entrante_id: Option<Uuid>,
    pub total_al_iniciar: Option<i32>,
    pub pendientes: Option<i64>,
}

impl<'a, K, E> MetadataKeyService<'a, K, E>
where
    K: MetadataKeyRepository,
    E: MetadataKeyEnvelopeRepository,
{
    /// `POST /admin/metadata-keys` — F-06. Misma regla de tope que F-33
    /// (`MaxNoOfActiveMetadataKeysRule`, máximo 2 activas): si ya hay 2, hay
    /// una rotación en curso y no se puede crear una tercera.
    pub async fn crear_clave_compartida(
        &self,
        actor_id: Uuid,
        id: Uuid,
        public_key_x25519: &[u8],
        fingerprint: &str,
        destinatarios: Vec<(Uuid, Vec<u8>)>,
    ) -> Result<MetadataKey, DomainError> {
        if public_key_x25519.len() != 32 {
            return Err(DomainError::ValidacionInvalida(
                "public_key_x25519 debe ser de 32 bytes".into(),
            ));
        }
        // H-29 (auditoría 2026-08-12): check-y-alta atómicos (lock de fila)
        // — antes, dos altas concurrentes podían ambas ver "menos de 2
        // activas" y terminar con 3+, corrompiendo el tope de la regla.
        let Some(clave) = self.claves.crear_si_no_excede(id, public_key_x25519, fingerprint, 2).await? else {
            return Err(DomainError::Conflict);
        };
        for (user_id, sealed) in destinatarios {
            self.envelopes.insertar(clave.id, user_id, &sealed).await?;
        }

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::MetadataKeyCreated, Some(actor_id))
                .con_sujeto("metadata_key", clave.id),
        ));

        Ok(clave)
    }

    pub async fn activas(&self) -> Result<Vec<MetadataKey>, DomainError> {
        Ok(self.claves.activas().await?)
    }

    /// `POST /admin/metadata-keys/{id}/members` — hallazgo real de uso:
    /// `crear_clave_compartida` sólo sellaba la privada para el propio admin
    /// creador, así que ningún otro usuario tenía nunca acceso real a una
    /// metadata key compartida (ergo, ningún recurso `shared_key` era
    /// compartible con nadie en la práctica). Esto agrega un miembro a una
    /// key ya activa sin necesidad de rotarla — el caller ya resolvió y
    /// reselló la privada client-side (mismo patrón que agregar un miembro a
    /// un grupo, `GroupService::agregar_con_envelopes`).
    pub async fn agregar_destinatario(
        &self,
        actor_id: Uuid,
        metadata_key_id: Uuid,
        user_id: Uuid,
        sealed_private_key: &[u8],
    ) -> Result<(), DomainError> {
        let clave = self.claves.buscar(metadata_key_id).await?.ok_or(DomainError::NotFound)?;
        if clave.expired_at.is_some() {
            return Err(DomainError::ValidacionInvalida("esta metadata key ya no está activa".into()));
        }

        self.envelopes.insertar(metadata_key_id, user_id, sealed_private_key).await.map_err(|e| match e {
            crate::error::RepoError::Conflict => DomainError::Conflict,
            otro => DomainError::Interno(otro),
        })?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::MetadataKeyMemberAdded, Some(actor_id))
                .con_sujeto("metadata_key", metadata_key_id)
                .con_metadata(serde_json::json!({ "user_id": user_id })),
        ));

        Ok(())
    }

    pub async fn envelope_propio(
        &self,
        metadata_key_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<Vec<u8>>, DomainError> {
        Ok(self
            .envelopes
            .buscar(metadata_key_id, user_id)
            .await?
            .map(|e| e.sealed_private_key))
    }

    /// `POST /admin/metadata-keys/rotate` — F-33. Exige exactamente 1 clave
    /// activa: 0 significa que no hay nada que rotar (F-06 todavía no se
    /// ejecutó), 2 significa que ya hay una rotación en curso.
    pub async fn iniciar_rotacion(
        &self,
        actor_id: Uuid,
        id_entrante: Uuid,
        public_key_x25519: &[u8],
        fingerprint: &str,
        destinatarios: Vec<(Uuid, Vec<u8>)>,
    ) -> Result<MetadataKey, DomainError> {
        if public_key_x25519.len() != 32 {
            return Err(DomainError::ValidacionInvalida(
                "public_key_x25519 debe ser de 32 bytes".into(),
            ));
        }

        // Pre-chequeo sólo para el mensaje de error correcto en el caso
        // común (sin carrera) — 0 activas y 2+ activas son errores
        // distintos (400 vs. 409) para quien llama. La mutación real es
        // atómica (`iniciar_rotacion_atomico`, H-29): si esto pasó pero el
        // estado cambió antes de esa llamada (carrera real), se trata como
        // 409 genérico — alguien más ya tocó el estado, hay que reintentar.
        match self.claves.activas().await?.as_slice() {
            [_unica] => {}
            [] => {
                return Err(DomainError::ValidacionInvalida(
                    "no hay ninguna metadata key compartida activa para rotar".into(),
                ));
            }
            _ => return Err(DomainError::Conflict),
        };

        // H-29: check-y-alta atómicos (lock de fila) — antes, dos
        // `iniciar_rotacion` concurrentes podían ambas ver "1 activa" y
        // crear su propia entrante, terminando con 3+ claves activas y
        // corrompiendo `estado_rotacion()`.
        let Some((saliente, entrante, _total_pendiente)) =
            self.claves.iniciar_rotacion_atomico(id_entrante, public_key_x25519, fingerprint).await?
        else {
            return Err(DomainError::Conflict);
        };

        for (user_id, sealed) in destinatarios {
            self.envelopes.insertar(entrante.id, user_id, &sealed).await?;
        }

        // Publicado después de confirmar en la base — un consumidor lento o
        // caído nunca invalida la rotación ya iniciada.
        let _ = self.eventos.send(DomainEvent::MetadataKeyRotationStarted {
            saliente_id: saliente.id,
            entrante_id: entrante.id,
        });
        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::MetadataKeyRotationStarted, Some(actor_id))
                .con_sujeto("metadata_key", entrante.id)
                .con_metadata(serde_json::json!({ "saliente_id": saliente.id, "entrante_id": entrante.id })),
        ));

        Ok(entrante)
    }

    pub async fn estado_rotacion(&self) -> Result<EstadoRotacion, DomainError> {
        let activas = self.claves.activas().await?;
        match activas.as_slice() {
            [saliente, entrante] => {
                let (saliente, entrante) = if saliente.resources_pendientes_al_iniciar.is_some() {
                    (saliente, entrante)
                } else {
                    (entrante, saliente)
                };
                let pendientes = self.claves.contar_recursos_con_clave(saliente.id).await?;
                Ok(EstadoRotacion {
                    activa: true,
                    saliente_id: Some(saliente.id),
                    entrante_id: Some(entrante.id),
                    total_al_iniciar: saliente.resources_pendientes_al_iniciar,
                    pendientes: Some(pendientes),
                })
            }
            _ => Ok(EstadoRotacion {
                activa: false,
                saliente_id: None,
                entrante_id: None,
                total_al_iniciar: None,
                pendientes: None,
            }),
        }
    }
}
