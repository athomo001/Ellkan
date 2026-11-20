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
            EventoAuditoria::nuevo(AuditEventType::DeviceTrusted, Some(user_id)).con_sujeto("trusted_device", dispositivo.id),
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
            EventoAuditoria::nuevo(AuditEventType::DeviceRevoked, Some(user_id)).con_sujeto("trusted_device", device_id),
        ));

        Ok(())
    }

    pub async fn politica(&self) -> Result<DeviceApprovalPolicy, DomainError> {
        Ok(self.policy.obtener().await?)
    }

    pub async fn actualizar_politica(&self, actor_id: Uuid, policy: DeviceApprovalPolicy) -> Result<(), DomainError> {
        self.policy.actualizar(&policy).await?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::DeviceApprovalPolicyUpdated, Some(actor_id)).con_metadata(serde_json::json!({
                "allow_peer_device_approval": policy.allow_peer_device_approval,
                "allow_admin_device_approval": policy.allow_admin_device_approval,
            })),
        ));

        Ok(())
    }

    /// `POST /auth/device-approval/request` — sin sesión, dispositivo nuevo.
    ///
    /// QA-15: un email sin cuenta recibe la misma respuesta que uno con cuenta
    /// (una solicitud "pendiente" que nunca se guarda ni nadie va a ver), y la
    /// política se mira antes que el email para que el 403 tampoco dependa de él.
    pub async fn solicitar_aprobacion(&self, email: &str, device_public_key: &[u8]) -> Result<ApprovalRequest, DomainError> {
        let politica = self.policy.obtener().await?;
        if !politica.allow_peer_device_approval {
            return Err(DomainError::PermissionDenied);
        }

        let fingerprint = fingerprint_de(device_public_key);
        let expires_at = OffsetDateTime::now_utc() + Duration::seconds(TTL_APROBACION_SEGUNDOS);
        let Some(usuario) = self.usuarios.buscar_por_email(email).await? else {
            return Ok(ApprovalRequest {
                id: Uuid::now_v7(),
                user_id: Uuid::nil(),
                device_public_key: device_public_key.to_vec(),
                fingerprint,
                status: "pending".into(),
                sealed_user_private_key: None,
                session_id: None,
                expires_at,
            });
        };
        Ok(self
            .solicitudes
            .crear(Uuid::now_v7(), usuario.id, device_public_key, &fingerprint, expires_at)
            .await?)
    }

    /// `GET /auth/device-approval/{id}` — poll sin sesión (endpoint nuevo,
    /// no listado en `03-api-contrato.md`, ver nota del plan de esta fase).
    ///
    /// QA-15: un id que no existe (la solicitud "pendiente" de un email sin
    /// cuenta, o una real ya purgada) no da 404: se contesta como una
    /// pendiente que vence a los `TTL_APROBACION_SEGUNDOS` de la hora que trae
    /// el propio UUIDv7. Una pendiente real vencida se informa como `expired`,
    /// igual que la inexistente después de ese plazo.
    pub async fn estado_aprobacion(&self, id: Uuid) -> Result<ApprovalRequest, DomainError> {
        let ahora = OffsetDateTime::now_utc();
        if let Some(mut solicitud) = self.solicitudes.buscar(id).await? {
            if solicitud.status == "pending" && solicitud.expires_at <= ahora {
                solicitud.status = "expired".into();
            }
            return Ok(solicitud);
        }
        let creada = id
            .get_timestamp()
            .and_then(|t| OffsetDateTime::from_unix_timestamp(t.to_unix().0 as i64).ok())
            .unwrap_or(ahora - Duration::seconds(TTL_APROBACION_SEGUNDOS));
        let expires_at = creada + Duration::seconds(TTL_APROBACION_SEGUNDOS);
        Ok(ApprovalRequest {
            id,
            user_id: Uuid::nil(),
            device_public_key: Vec::new(),
            fingerprint: String::new(),
            status: if expires_at > ahora { "pending" } else { "expired" }.into(),
            sealed_user_private_key: None,
            session_id: None,
            expires_at,
        })
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
    pub async fn aprobar(&self, actor_id: Uuid, approval_request_id: Uuid, sealed_user_private_key: &[u8]) -> Result<(), DomainError> {
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
