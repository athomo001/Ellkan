// Autor: Athan Espinoza

//! Service de Emergency Access (F-36) — nunca importa `axum`. El servidor
//! nunca sella ni desella `sealed_material`: el titular ya lo selló
//! client-side contra la clave pública X25519 del contacto elegido, mismo
//! criterio que compartir un recurso (F-05/F-11). Sólo autoriza *cuándo*
//! el contacto puede leer esos bytes opacos — tras aprobación explícita del
//! titular, o al vencer el plazo sin respuesta (job programado).

use uuid::Uuid;

use crate::audit::models::{AuditEventType, EventoAuditoria};
use crate::error::DomainError;
use crate::eventos::{DomainEvent, EmisorDeEventos};

use super::models::{EmergencyAccess, RecursoDelTitular};
use super::repository::{EmergencyAccessPolicyRepository, EmergencyAccessRepository, EmergencyAccessRequestRepository};

pub struct EmergencyAccessService<'a, P, EA, R> {
    pub policy: &'a P,
    pub accesos: &'a EA,
    pub requests: &'a R,
    pub eventos: EmisorDeEventos,
}

impl<'a, P, EA, R> EmergencyAccessService<'a, P, EA, R>
where
    P: EmergencyAccessPolicyRepository,
    EA: EmergencyAccessRepository,
    R: EmergencyAccessRequestRepository,
{
    pub async fn politica(&self) -> Result<bool, DomainError> {
        Ok(self.policy.habilitado().await?)
    }

    pub async fn actualizar_politica(&self, actor_id: Uuid, habilitado: bool) -> Result<(), DomainError> {
        self.policy.actualizar(habilitado).await?;
        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::EmergencyAccessPolicyUpdated, Some(actor_id))
                .con_metadata(serde_json::json!({ "enabled": habilitado })),
        ));
        Ok(())
    }

    pub async fn designar(
        &self,
        granter_id: Uuid,
        grantee_id: Uuid,
        access_level: &str,
        sealed_material: Vec<u8>,
        wait_time_days: i32,
    ) -> Result<EmergencyAccess, DomainError> {
        if !self.policy.habilitado().await? {
            return Err(DomainError::PermissionDenied);
        }
        if access_level != "view" && access_level != "takeover" {
            return Err(DomainError::ValidacionInvalida("access_level debe ser 'view' o 'takeover'".into()));
        }
        if wait_time_days < 1 {
            return Err(DomainError::ValidacionInvalida("wait_time_days debe ser al menos 1".into()));
        }
        if grantee_id == granter_id {
            return Err(DomainError::ValidacionInvalida("no podés designarte a vos mismo".into()));
        }

        let acceso = self.accesos.crear(granter_id, grantee_id, access_level, &sealed_material, wait_time_days).await?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::EmergencyAccessDesignated, Some(granter_id))
                .con_sujeto("emergency_access", acceso.id)
                .con_metadata(serde_json::json!({ "grantee_id": grantee_id, "access_level": access_level })),
        ));

        Ok(acceso)
    }

    /// Pendiente #131: ver `EmergencyAccessRepository::personas_relacionadas`.
    pub async fn personas_relacionadas(&self, user_id: Uuid) -> Result<Vec<super::models::PersonaEmergencia>, DomainError> {
        Ok(self.accesos.personas_relacionadas(user_id).await?)
    }

    pub async fn listar(&self, user_id: Uuid) -> Result<Vec<(EmergencyAccess, Option<String>, bool)>, DomainError> {
        let filas = self.accesos.listar_por_titular_o_contacto(user_id).await?;
        let mut resultado = Vec::with_capacity(filas.len());
        for acceso in filas {
            let ultima = self.requests.ultima_de(acceso.id).await?;
            let estado_solicitud = ultima.as_ref().map(|r| r.status.clone());
            let puede_leer_material =
                acceso.grantee_id == user_id && ultima.as_ref().is_some_and(|r| r.status == "approved" || r.status == "granted_by_timeout");
            resultado.push((acceso, estado_solicitud, puede_leer_material));
        }
        Ok(resultado)
    }

    /// F-36 (#134): la bóveda del titular para su contacto, sólo lectura.
    /// Exige lo mismo que entregar `sealed_material` en `listar`: ser el
    /// contacto y tener la última solicitud aprobada o concedida por plazo.
    /// Si el titular revoca, la fila desaparece y esto da 404. Cada lectura
    /// se audita (actor = contacto, sujeto = la relación, con el titular).
    /// No hay endpoints de escritura: con `view` ni con `takeover` el
    /// contacto edita o comparte los recursos del titular por esta vía.
    pub async fn boveda(&self, actor_id: Uuid, id: Uuid) -> Result<(EmergencyAccess, Vec<RecursoDelTitular>), DomainError> {
        let acceso = self.acceso_concedido(actor_id, id).await?;
        let recursos = self.accesos.boveda_del_titular(acceso.granter_id).await?;
        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::EmergencyAccessVaultViewed, Some(actor_id))
                .con_sujeto("emergency_access", id)
                .con_metadata(serde_json::json!({ "granter_id": acceso.granter_id, "resources": recursos.len() })),
        ));
        Ok((acceso, recursos))
    }

    /// La relación `id` si `actor_id` es su contacto y la última solicitud
    /// está aprobada o concedida por plazo. 404 a cualquier otra persona (ni
    /// se entera de que existe); 403 al contacto sin acceso concedido.
    async fn acceso_concedido(&self, actor_id: Uuid, id: Uuid) -> Result<EmergencyAccess, DomainError> {
        let acceso = self.accesos.buscar(id).await?.ok_or(DomainError::NotFound)?;
        if acceso.grantee_id != actor_id {
            return Err(DomainError::NotFound);
        }
        let concedido = self
            .requests
            .ultima_de(id)
            .await?
            .is_some_and(|r| r.status == "approved" || r.status == "granted_by_timeout");
        if !concedido {
            return Err(DomainError::PermissionDenied);
        }
        Ok(acceso)
    }

    /// F-36 (#134), `takeover`: autoriza al contacto a fijarle una passphrase
    /// nueva al titular. Sólo con nivel `takeover` y el acceso concedido. El
    /// reemplazo en sí (prueba de posesión con la Ed25519 del titular, que el
    /// contacto tiene por `sealed_material`, y la rotación de
    /// `security_stamp`, que cierra las sesiones del titular) lo hace el
    /// handler con las mismas piezas que `POST /me/change-passphrase`.
    pub async fn autorizar_takeover(&self, actor_id: Uuid, id: Uuid) -> Result<EmergencyAccess, DomainError> {
        let acceso = self.acceso_concedido(actor_id, id).await?;
        if acceso.access_level != "takeover" {
            return Err(DomainError::PermissionDenied);
        }
        Ok(acceso)
    }

    pub fn registrar_takeover(&self, actor_id: Uuid, acceso: &EmergencyAccess) {
        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::EmergencyAccessTakeover, Some(actor_id))
                .con_sujeto("emergency_access", acceso.id)
                .con_metadata(serde_json::json!({ "granter_id": acceso.granter_id })),
        ));
    }

    pub async fn aceptar(&self, actor_id: Uuid, id: Uuid) -> Result<(), DomainError> {
        let acceso = self.accesos.buscar(id).await?.ok_or(DomainError::NotFound)?;
        if acceso.grantee_id != actor_id {
            return Err(DomainError::PermissionDenied);
        }
        if acceso.status != "invited" {
            return Err(DomainError::Conflict);
        }
        self.accesos.marcar_status(id, "accepted").await?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::EmergencyAccessAccepted, Some(actor_id)).con_sujeto("emergency_access", id),
        ));
        Ok(())
    }

    pub async fn revocar(&self, actor_id: Uuid, id: Uuid) -> Result<(), DomainError> {
        let acceso = self.accesos.buscar(id).await?.ok_or(DomainError::NotFound)?;
        if acceso.granter_id != actor_id {
            return Err(DomainError::PermissionDenied);
        }
        self.accesos.eliminar(id).await?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::EmergencyAccessRevoked, Some(actor_id)).con_sujeto("emergency_access", id),
        ));
        Ok(())
    }

    pub async fn solicitar(&self, actor_id: Uuid, id: Uuid) -> Result<(), DomainError> {
        let acceso = self.accesos.buscar(id).await?.ok_or(DomainError::NotFound)?;
        if acceso.grantee_id != actor_id {
            return Err(DomainError::PermissionDenied);
        }
        if acceso.status == "invited" {
            return Err(DomainError::ValidacionInvalida("el contacto todavía no aceptó esta designación".into()));
        }

        // H-17 (auditoría 2026-08-12): `crear` ya mapea la violación del
        // índice único parcial ("un solo pending por emergency_access") a
        // `RepoError::Conflict` — pero el `?` genérico de acá lo envolvía en
        // `DomainError::Interno` (500 sin explicación) en vez del 409 que
        // realmente es. Mapeo explícito para que se vea como lo que es: dos
        // solicitudes concurrentes, la segunda llega tarde.
        self.requests.crear(id).await.map_err(|e| match e {
            crate::error::RepoError::Conflict => DomainError::Conflict,
            otro => DomainError::Interno(otro),
        })?;

        // QA-22: el titular se entera ahora, no cuando el job ya lo concedió.
        match self.requests.aviso_de(id).await {
            Ok(Some(aviso)) => {
                let _ = self.eventos.send(aviso.evento(false));
            }
            Ok(None) => {}
            Err(e) => tracing::error!(error = %e, emergency_access_id = %id, "no se pudo armar el aviso al titular"),
        }
        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::EmergencyAccessRequested, Some(actor_id)).con_sujeto("emergency_access", id),
        ));
        Ok(())
    }

    async fn resolver_pendiente(
        &self,
        actor_id: Uuid,
        id: Uuid,
        nuevo_status: &'static str,
        evento: AuditEventType,
    ) -> Result<(), DomainError> {
        let acceso = self.accesos.buscar(id).await?.ok_or(DomainError::NotFound)?;
        if acceso.granter_id != actor_id {
            return Err(DomainError::PermissionDenied);
        }
        let pendiente = self.requests.pendiente_de(id).await?.ok_or(DomainError::NotFound)?;
        if !self.requests.resolver(pendiente.id, nuevo_status).await? {
            return Err(DomainError::Conflict);
        }
        if nuevo_status == "approved" {
            self.accesos.marcar_status(id, "confirmed").await?;
        }

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(evento, Some(actor_id)).con_sujeto("emergency_access", id),
        ));
        Ok(())
    }

    pub async fn aprobar(&self, actor_id: Uuid, id: Uuid) -> Result<(), DomainError> {
        self.resolver_pendiente(actor_id, id, "approved", AuditEventType::EmergencyAccessApproved).await
    }

    pub async fn rechazar(&self, actor_id: Uuid, id: Uuid) -> Result<(), DomainError> {
        self.resolver_pendiente(actor_id, id, "rejected", AuditEventType::EmergencyAccessRejected).await
    }
}
