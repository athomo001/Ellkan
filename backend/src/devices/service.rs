// Autor: Athan Espinoza

//! Service de Trusted Device (F-37) — nunca importa `axum`. El servidor
//! nunca sella ni desella nada: sólo autoriza y mueve bytes opacos entre
//! dispositivos del mismo usuario, más el cómputo de un fingerprint corto
//! (hash del `device_public_key`) para que ambos dispositivos lo comparen
//! visualmente antes de aprobar.

use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::audit::models::{AuditEventType, EventoAuditoria};
use crate::auth::repository::{SessionRepository, UserRepository};
use crate::error::DomainError;
use crate::eventos::{DomainEvent, EmisorDeEventos};

use super::models::{ApprovalRequest, DeviceApprovalPolicy, TrustedDevice};
use super::repository::{ApprovalRequestRepository, DeviceApprovalPolicyRepository, TrustedDeviceRepository};

const TTL_APROBACION_SEGUNDOS: i64 = 300;

fn fingerprint_de(device_public_key: &[u8]) -> String {
    hex::encode(&Sha256::digest(device_public_key)[..8])
}

pub struct DeviceService<'a, T, A, PR, S, U> {
    pub confiables: &'a T,
    pub solicitudes: &'a A,
    pub policy: &'a PR,
    pub sesiones: &'a S,
    pub usuarios: &'a U,
    pub eventos: EmisorDeEventos,
}

impl<'a, T, A, PR, S, U> DeviceService<'a, T, A, PR, S, U>
where
    T: TrustedDeviceRepository,
    A: ApprovalRequestRepository,
    PR: DeviceApprovalPolicyRepository,
    S: SessionRepository,
    U: UserRepository,
{
    /// `POST /me/devices/trust` — el dispositivo actual, ya logueado, ya
    /// selló su propia clave (desbloqueada en memoria) para sí mismo.
    pub async fn marcar_confiable(
        &self,
        user_id: Uuid,
        device_public_key: &[u8],
        sealed_user_private_key: &[u8],
        label: Option<&str>,
    ) -> Result<TrustedDevice, DomainError> {
        let dispositivo = self
            .confiables
            .crear(Uuid::now_v7(), user_id, device_public_key, sealed_user_private_key, label)
            .await?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::DeviceTrusted, Some(user_id))
                .con_sujeto("trusted_device", dispositivo.id),
        ));

        Ok(dispositivo)
    }

    pub async fn listar_confiables(&self, user_id: Uuid) -> Result<Vec<TrustedDevice>, DomainError> {
        Ok(self.confiables.listar_de(user_id).await?)
    }

    pub async fn revocar(&self, user_id: Uuid, device_id: Uuid) -> Result<(), DomainError> {
        let dispositivo = self.confiables.buscar(device_id).await?.ok_or(DomainError::NotFound)?;
        if dispositivo.user_id != user_id {
            return Err(DomainError::PermissionDenied);
        }
        self.confiables.revocar(device_id).await?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::DeviceRevoked, Some(user_id))
                .con_sujeto("trusted_device", device_id),
        ));

        Ok(())
    }

    pub async fn politica(&self) -> Result<DeviceApprovalPolicy, DomainError> {
        Ok(self.policy.obtener().await?)
    }

    pub async fn actualizar_politica(
        &self,
        actor_id: Uuid,
        policy: DeviceApprovalPolicy,
    ) -> Result<(), DomainError> {
        self.policy.actualizar(&policy).await?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::DeviceApprovalPolicyUpdated, Some(actor_id)).con_metadata(
                serde_json::json!({
                    "allow_peer_device_approval": policy.allow_peer_device_approval,
                    "allow_admin_device_approval": policy.allow_admin_device_approval,
                }),
            ),
        ));

        Ok(())
    }

    /// `POST /auth/device-approval/request` — sin sesión, dispositivo nuevo.
    pub async fn solicitar_aprobacion(
        &self,
        user_id: Uuid,
        device_public_key: &[u8],
    ) -> Result<ApprovalRequest, DomainError> {
        let politica = self.policy.obtener().await?;
        if !politica.allow_peer_device_approval {
            return Err(DomainError::PermissionDenied);
        }

        let fingerprint = fingerprint_de(device_public_key);
        let expires_at = OffsetDateTime::now_utc() + Duration::seconds(TTL_APROBACION_SEGUNDOS);
        Ok(self
            .solicitudes
            .crear(Uuid::now_v7(), user_id, device_public_key, &fingerprint, expires_at)
            .await?)
    }

    /// `GET /auth/device-approval/{id}` — poll sin sesión (endpoint nuevo,
    /// no listado en `03-api-contrato.md`, ver nota del plan de esta fase).
    pub async fn estado_aprobacion(&self, id: Uuid) -> Result<ApprovalRequest, DomainError> {
        self.solicitudes.buscar(id).await?.ok_or(DomainError::NotFound)
    }

    /// `GET /me/devices/pending-approvals` — autenticado (endpoint nuevo,
    /// mismo criterio).
    pub async fn listar_pendientes(&self, user_id: Uuid) -> Result<Vec<ApprovalRequest>, DomainError> {
        Ok(self.solicitudes.listar_pendientes_de(user_id).await?)
    }

    /// `POST /auth/device-approval/{id}/approve` — llamado por un
    /// dispositivo ya confiable del **mismo** usuario (nunca aprueba el
    /// dispositivo de otra persona). Mintea la sesión que el dispositivo
    /// nuevo termina usando, guarda el envelope sellado, y da de alta el
    /// dispositivo nuevo como confiable (ya puede aprobar a otros).
    pub async fn aprobar(
        &self,
        actor_id: Uuid,
        approval_request_id: Uuid,
        sealed_user_private_key: &[u8],
    ) -> Result<(), DomainError> {
        let politica = self.policy.obtener().await?;
        if !politica.allow_peer_device_approval {
            return Err(DomainError::PermissionDenied);
        }

        let solicitud = self.solicitudes.buscar(approval_request_id).await?.ok_or(DomainError::NotFound)?;
        if solicitud.user_id != actor_id {
            return Err(DomainError::PermissionDenied);
        }
        if solicitud.status != "pending" {
            return Err(DomainError::Conflict);
        }

        let usuario = self.usuarios.buscar_por_id(actor_id).await?.ok_or(DomainError::NotFound)?;
        let sesion = self.sesiones.crear(usuario.id, usuario.security_stamp).await?;

        let aplicado = self.solicitudes.aprobar(approval_request_id, sealed_user_private_key, sesion.id).await?;
        if !aplicado {
            return Err(DomainError::Conflict);
        }

        self.confiables
            .crear(Uuid::now_v7(), solicitud.user_id, &solicitud.device_public_key, sealed_user_private_key, None)
            .await?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::DeviceApprovalGranted, Some(actor_id))
                .con_sujeto("device_approval_request", approval_request_id),
        ));

        Ok(())
    }
}
