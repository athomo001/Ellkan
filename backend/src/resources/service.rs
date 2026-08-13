// Autor: Athan Espinoza

//! Service de recursos — nunca importa `axum`. El servidor nunca ve
//! `metadata`/secreto en claro ni una DEK sin sellar: sólo mueve bytes ya
//! cifrados client-side (F-05, F-06, F-07).

use uuid::Uuid;

use crate::admin::repository::RoleRepository;
use crate::audit::models::{AuditEventType, EventoAuditoria};
use crate::error::DomainError;
use crate::eventos::{DomainEvent, EmisorDeEventos};
use crate::folders::repository::FolderItemRepository;
use crate::groups::repository::GroupMemberRepository;

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

pub struct ResourceService<'a, R, E, P, T, FI, GM, RR> {
    pub recursos: &'a R,
    pub envolturas: &'a E,
    pub permisos: &'a P,
    pub tipos_recurso: &'a T,
    pub items: &'a FI,
    pub grupos: &'a GM,
    pub roles: &'a RR,
    pub eventos: EmisorDeEventos,
}

#[allow(clippy::too_many_arguments)]
impl<'a, R, E, P, T, FI, GM, RR> ResourceService<'a, R, E, P, T, FI, GM, RR>
where
    R: ResourceRepository,
    E: SecretEnvelopeRepository,
    P: PermissionRepository,
    T: ResourceTypeRepository,
    FI: FolderItemRepository,
    GM: GroupMemberRepository,
    RR: RoleRepository,
{
    /// 2026-08-11: `Some(group_id)` si `resource_id` vive en alguna carpeta
    /// compartida con un grupo (de cualquier usuario que lo tenga
    /// posicionado ahí) — determina si el borrado exige ser admin de ESE
    /// grupo en vez del criterio de `owner` de siempre.
    async fn grupo_dueno_de_carpeta(&self, resource_id: Uuid) -> Result<Option<Uuid>, DomainError> {
        for folder_id in self.items.carpetas_de_recurso(resource_id).await? {
            if let Some(group_id) = self.permisos.grupo_grantee_de("folder", folder_id).await? {
                return Ok(Some(group_id));
            }
        }
        Ok(None)
    }

    /// `DELETE /resources/{id}` (2026-08-11, antes no existía ningún camino
    /// para borrar un recurso real). Si vive en una carpeta de grupo, exige
    /// admin de ESE grupo o de organización — el `owner` individual del
    /// recurso NO alcanza ahí (hallazgo real de uso: "un user no puede
    /// borrar contraseñas de una carpeta, sólo el admin de grupo y el admin
    /// general"). Fuera de una carpeta de grupo, cae al criterio de
    /// siempre: `owner`.
    pub async fn eliminar(&self, resource_id: Uuid, actor_id: Uuid) -> Result<(), DomainError> {
        self.recursos.buscar(resource_id).await?.ok_or(DomainError::NotFound)?;

        let es_admin_org = self.roles.usuario_tiene_permiso(actor_id, "*").await?;
        if !es_admin_org {
            match self.grupo_dueno_de_carpeta(resource_id).await? {
                Some(group_id) => {
                    if !self.grupos.grupos_administrados_por(actor_id).await?.contains(&group_id) {
                        return Err(DomainError::PermissionDenied);
                    }
                }
                None => {
                    if !self
                        .permisos
                        .tiene_permiso("resource", resource_id, actor_id, NivelPermiso::Owner.as_db_str())
                        .await?
                    {
                        return Err(DomainError::PermissionDenied);
                    }
                }
            }
        }

        self.recursos.marcar_eliminado(resource_id).await?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::ResourceDeleted, Some(actor_id)).con_sujeto("resource", resource_id),
        ));

        Ok(())
    }

    /// 2026-08-11: `true` si `actor_id` podría borrar `resource_id` con la
    /// misma regla de `eliminar` — usado para exponer `puede_borrar` en
    /// `RecursoResponse` y así el frontend no muestre un botón que siempre
    /// va a devolver 403.
    pub async fn puede_borrar(&self, resource_id: Uuid, actor_id: Uuid) -> Result<bool, DomainError> {
        if self.roles.usuario_tiene_permiso(actor_id, "*").await? {
            return Ok(true);
        }
        match self.grupo_dueno_de_carpeta(resource_id).await? {
            Some(group_id) => Ok(self.grupos.grupos_administrados_por(actor_id).await?.contains(&group_id)),
            None => {
                self.permisos.tiene_permiso("resource", resource_id, actor_id, NivelPermiso::Owner.as_db_str()).await.map_err(DomainError::from)
            }
        }
    }
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
            .otorgar("resource", recurso.id, "user", owner_id, NivelPermiso::Owner.as_db_str())
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
            .otorgar("resource", resource_id, "user", recipient_id, nivel.as_db_str())
            .await?;
        // H-31: ver comentario en `ResourceRepository::tocar_updated_at`.
        self.recursos.tocar_updated_at(resource_id).await?;

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

        // Sólo usuarios por ahora (compartir con grupos sigue siendo el
        // mecanismo aparte de `GroupService`, F-12) — `otorgar` ya es upsert.
        if grantee_type != "user" {
            return Err(DomainError::ValidacionInvalida("cambiar nivel sólo soportado para destinatarios usuario".into()));
        }
        // H-26: check-y-mutación atómicos (lock de fila) — antes, dos
        // llamadas concurrentes de "bajar a Alice" y "bajar a Bob" (los dos
        // únicos Owners) podían pasar el chequeo de "existe otro owner" cada
        // una viendo al otro todavía sin bajar, dejando el recurso sin
        // ningún Owner de forma permanente.
        if !self
            .permisos
            .cambiar_nivel_si_queda_otro_owner("resource", resource_id, grantee_type, grantee_id, nuevo_nivel.as_db_str())
            .await?
        {
            return Err(DomainError::ValidacionInvalida("el recurso se quedaría sin ningún Owner".into()));
        }
        // H-31: ver comentario en `ResourceRepository::tocar_updated_at`.
        self.recursos.tocar_updated_at(resource_id).await?;

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
        // H-26: ver comentario equivalente en `cambiar_nivel`.
        if !self.permisos.revocar_si_queda_otro_owner("resource", resource_id, grantee_type, grantee_id).await? {
            return Err(DomainError::ValidacionInvalida("el recurso se quedaría sin ningún Owner".into()));
        }
        // H-31: ver comentario en `ResourceRepository::tocar_updated_at`.
        self.recursos.tocar_updated_at(resource_id).await?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::PermissionGranted, Some(actor_id))
                .con_sujeto("resource", resource_id)
                .con_metadata(serde_json::json!({ "grantee_type": grantee_type, "grantee_id": grantee_id, "revoked": true })),
        ));
        Ok(())
    }

    /// `POST /resources/{id}/leave` — 2026-08-13, hallazgo real de uso: a
    /// quien le comparten un recurso (grantee directo, no Owner) no tenía
    /// ninguna forma de sacárselo de su propio vault sin que el dueño lo
    /// revocara primero (`revocar_permiso` exige ser Owner para revocar a
    /// cualquiera). Acá sólo se revoca la propia membresía directa, así que
    /// no hace falta ser Owner — salvo que la propia membresía SEA de nivel
    /// `owner`, ahí aplica la misma regla de "no te podés quedar sin ningún
    /// Owner" que ya usa `revocar_permiso`/`cambiar_nivel`. Si el acceso
    /// viene sólo por un grupo (sin fila directa `grantee_type='user'` para
    /// este actor), no hay nada que revocar acá — salir del grupo es el
    /// camino real, se lo dice explícito en vez de un no-op silencioso.
    pub async fn salir(&self, resource_id: Uuid, actor_id: Uuid) -> Result<(), DomainError> {
        let grantees = self.permisos.listar("resource", resource_id).await?;
        let propio = grantees.iter().find(|g| g.grantee_type == "user" && g.grantee_id == actor_id).ok_or_else(|| {
            DomainError::ValidacionInvalida(
                "no tenés un acceso directo a este recurso — si lo ves por ser miembro de un grupo, salí del grupo en cambio".into(),
            )
        })?;

        if propio.level == NivelPermiso::Owner.as_db_str() {
            // H-26: ver comentario equivalente en `cambiar_nivel`.
            if !self.permisos.revocar_si_queda_otro_owner("resource", resource_id, "user", actor_id).await? {
                return Err(DomainError::ValidacionInvalida("no podés salir: sos el único Owner de este recurso".into()));
            }
        } else {
            self.permisos.revocar("resource", resource_id, "user", actor_id).await?;
        }
        // H-31: ver comentario en `ResourceRepository::tocar_updated_at`.
        self.recursos.tocar_updated_at(resource_id).await?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::PermissionGranted, Some(actor_id))
                .con_sujeto("resource", resource_id)
                .con_metadata(serde_json::json!({ "grantee_type": "user", "grantee_id": actor_id, "revoked": true, "self_service": true })),
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
