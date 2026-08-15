// Autor: Athan Espinoza

#![allow(async_fn_in_trait)]

use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::RepoError;

use super::models::{ApprovalRequest, DeviceApprovalPolicy, TrustedDevice};

pub trait TrustedDeviceRepository {
    async fn crear(
        &self,
        id: Uuid,
        user_id: Uuid,
        device_public_key: &[u8],
        sealed_user_private_key: &[u8],
        label: Option<&str>,
    ) -> Result<TrustedDevice, RepoError>;

    async fn listar_de(&self, user_id: Uuid) -> Result<Vec<TrustedDevice>, RepoError>;

    async fn buscar(&self, id: Uuid) -> Result<Option<TrustedDevice>, RepoError>;

    /// Revoca — pone `revoked_at` y limpia `sealed_user_private_key` (F-37:
    /// "revocar borra..."), sin borrar la fila (queda el registro de que
    /// existió).
    async fn revocar(&self, id: Uuid) -> Result<(), RepoError>;
}

pub trait ApprovalRequestRepository {
    #[allow(clippy::too_many_arguments)]
    async fn crear(
        &self,
        id: Uuid,
        user_id: Uuid,
        device_public_key: &[u8],
        fingerprint: &str,
        expires_at: OffsetDateTime,
    ) -> Result<ApprovalRequest, RepoError>;

    async fn buscar(&self, id: Uuid) -> Result<Option<ApprovalRequest>, RepoError>;

    async fn listar_pendientes_de(&self, user_id: Uuid) -> Result<Vec<ApprovalRequest>, RepoError>;

    /// Aprueba de forma condicionada: sólo aplica si la fila seguía
    /// `pending` y no vencida — devuelve `false` si no (ya resuelta, o
    /// vencida), para que el Service pueda distinguir "ya no existe una
    /// solicitud pendiente" sin una carrera entre dos aprobaciones
    /// simultáneas.
    async fn aprobar(
        &self,
        id: Uuid,
        sealed_user_private_key: &[u8],
        session_id: Uuid,
    ) -> Result<bool, RepoError>;
}

pub trait DeviceApprovalPolicyRepository {
    async fn obtener(&self) -> Result<DeviceApprovalPolicy, RepoError>;

    async fn actualizar(&self, policy: &DeviceApprovalPolicy) -> Result<(), RepoError>;
}

#[derive(Clone)]
pub struct PgTrustedDeviceRepository {
    pub pool: sqlx::PgPool,
}

impl TrustedDeviceRepository for PgTrustedDeviceRepository {
    async fn crear(
        &self,
        id: Uuid,
        user_id: Uuid,
        device_public_key: &[u8],
        sealed_user_private_key: &[u8],
        label: Option<&str>,
    ) -> Result<TrustedDevice, RepoError> {
        let fila = sqlx::query!(
            r#"
            insert into trusted_devices (id, user_id, device_public_key, sealed_user_private_key, label)
            values ($1, $2, $3, $4, $5)
            returning id, user_id, device_public_key, label, created_at, revoked_at
            "#,
            id,
            user_id,
            device_public_key,
            sealed_user_private_key,
            label,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(TrustedDevice {
            id: fila.id,
            user_id: fila.user_id,
            device_public_key: fila.device_public_key,
            label: fila.label,
            created_at: fila.created_at,
            revoked_at: fila.revoked_at,
        })
    }

    async fn listar_de(&self, user_id: Uuid) -> Result<Vec<TrustedDevice>, RepoError> {
        let filas = sqlx::query!(
            r#"
            select id, user_id, device_public_key, label, created_at, revoked_at
            from trusted_devices where user_id = $1 order by created_at
            "#,
            user_id,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(filas
            .into_iter()
            .map(|f| TrustedDevice {
                id: f.id,
                user_id: f.user_id,
                device_public_key: f.device_public_key,
                label: f.label,
                created_at: f.created_at,
                revoked_at: f.revoked_at,
            })
            .collect())
    }

    async fn buscar(&self, id: Uuid) -> Result<Option<TrustedDevice>, RepoError> {
        let fila = sqlx::query!(
            r#"select id, user_id, device_public_key, label, created_at, revoked_at from trusted_devices where id = $1"#,
            id,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(fila.map(|f| TrustedDevice {
            id: f.id,
            user_id: f.user_id,
            device_public_key: f.device_public_key,
            label: f.label,
            created_at: f.created_at,
            revoked_at: f.revoked_at,
        }))
    }

    async fn revocar(&self, id: Uuid) -> Result<(), RepoError> {
        sqlx::query!(
            r#"
            update trusted_devices set revoked_at = now(), sealed_user_private_key = null
            where id = $1 and revoked_at is null
            "#,
            id,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct PgApprovalRequestRepository {
    pub pool: sqlx::PgPool,
}

impl ApprovalRequestRepository for PgApprovalRequestRepository {
    async fn crear(
        &self,
        id: Uuid,
        user_id: Uuid,
        device_public_key: &[u8],
        fingerprint: &str,
        expires_at: OffsetDateTime,
    ) -> Result<ApprovalRequest, RepoError> {
        let fila = sqlx::query!(
            r#"
            insert into device_approval_requests (id, user_id, device_public_key, fingerprint, expires_at)
            values ($1, $2, $3, $4, $5)
            returning id, user_id, device_public_key, fingerprint, status,
                      sealed_user_private_key, session_id, expires_at
            "#,
            id,
            user_id,
            device_public_key,
            fingerprint,
            expires_at,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(ApprovalRequest {
            id: fila.id,
            user_id: fila.user_id,
            device_public_key: fila.device_public_key,
            fingerprint: fila.fingerprint,
            status: fila.status,
            sealed_user_private_key: fila.sealed_user_private_key,
            session_id: fila.session_id,
            expires_at: fila.expires_at,
        })
    }

    async fn buscar(&self, id: Uuid) -> Result<Option<ApprovalRequest>, RepoError> {
        let fila = sqlx::query!(
            r#"
            select id, user_id, device_public_key, fingerprint, status,
                   sealed_user_private_key, session_id, expires_at
            from device_approval_requests where id = $1
            "#,
            id,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(fila.map(|f| ApprovalRequest {
            id: f.id,
            user_id: f.user_id,
            device_public_key: f.device_public_key,
            fingerprint: f.fingerprint,
            status: f.status,
            sealed_user_private_key: f.sealed_user_private_key,
            session_id: f.session_id,
            expires_at: f.expires_at,
        }))
    }

    async fn listar_pendientes_de(&self, user_id: Uuid) -> Result<Vec<ApprovalRequest>, RepoError> {
        let filas = sqlx::query!(
            r#"
            select id, user_id, device_public_key, fingerprint, status,
                   sealed_user_private_key, session_id, expires_at
            from device_approval_requests
            where user_id = $1 and status = 'pending' and expires_at > now()
            order by created_at
            "#,
            user_id,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(filas
            .into_iter()
            .map(|f| ApprovalRequest {
                id: f.id,
                user_id: f.user_id,
                device_public_key: f.device_public_key,
                fingerprint: f.fingerprint,
                status: f.status,
                sealed_user_private_key: f.sealed_user_private_key,
                session_id: f.session_id,
                expires_at: f.expires_at,
            })
            .collect())
    }

    async fn aprobar(
        &self,
        id: Uuid,
        sealed_user_private_key: &[u8],
        session_id: Uuid,
    ) -> Result<bool, RepoError> {
        let resultado = sqlx::query!(
            r#"
            update device_approval_requests
            set status = 'approved', sealed_user_private_key = $2, session_id = $3
            where id = $1 and status = 'pending' and expires_at > now()
            "#,
            id,
            sealed_user_private_key,
            session_id,
        )
        .execute(&self.pool)
        .await?;
        Ok(resultado.rows_affected() == 1)
    }
}

#[derive(Clone)]
pub struct PgDeviceApprovalPolicyRepository {
    pub pool: sqlx::PgPool,
}

impl DeviceApprovalPolicyRepository for PgDeviceApprovalPolicyRepository {
    async fn obtener(&self) -> Result<DeviceApprovalPolicy, RepoError> {
        let fila = sqlx::query!(
            r#"select allow_peer_device_approval, allow_admin_device_approval from organizations where id = 1"#,
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(DeviceApprovalPolicy {
            allow_peer_device_approval: fila.allow_peer_device_approval,
            allow_admin_device_approval: fila.allow_admin_device_approval,
        })
    }

    async fn actualizar(&self, policy: &DeviceApprovalPolicy) -> Result<(), RepoError> {
        sqlx::query!(
            r#"
            update organizations
            set allow_peer_device_approval = $1, allow_admin_device_approval = $2
            where id = 1
            "#,
            policy.allow_peer_device_approval,
            policy.allow_admin_device_approval,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
