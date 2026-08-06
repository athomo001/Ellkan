// Autor: Athan Espinoza

#![allow(async_fn_in_trait)]

use uuid::Uuid;

use crate::error::RepoError;

use super::models::{AccountRecoveryPolicy, Escrow, OrgRecoveryKey, RecoveryRequest};

pub trait AccountRecoveryPolicyRepository {
    async fn obtener(&self) -> Result<AccountRecoveryPolicy, RepoError>;
    async fn actualizar(&self, policy: &AccountRecoveryPolicy) -> Result<(), RepoError>;
}

pub trait OrgRecoveryKeyRepository {
    /// Genera (una sola vez, lazy) el keypair X25519 de recuperación
    /// organizacional si todavía no existe, y lo devuelve.
    async fn obtener_o_crear(
        &self,
        generar: impl FnOnce() -> (Vec<u8>, Vec<u8>, Vec<u8>),
    ) -> Result<OrgRecoveryKey, RepoError>;
}

pub trait EscrowRepository {
    /// Re-enrolar reemplaza el escrow anterior (`on conflict (user_id)`) —
    /// un usuario sólo tiene un escrow activo a la vez.
    async fn upsert(
        &self,
        user_id: Uuid,
        sealed_private_key_for_org: &[u8],
        org_recovery_key_id: i32,
        approval_threshold: i32,
    ) -> Result<Escrow, RepoError>;

    async fn buscar_por_usuario(&self, user_id: Uuid) -> Result<Option<Escrow>, RepoError>;
    async fn buscar(&self, id: Uuid) -> Result<Option<Escrow>, RepoError>;
}

pub trait RecoveryRequestRepository {
    async fn crear(
        &self,
        escrow_id: Uuid,
        requested_by: Option<Uuid>,
        requester_public_key_x25519: &[u8],
    ) -> Result<RecoveryRequest, RepoError>;

    async fn buscar(&self, id: Uuid) -> Result<Option<RecoveryRequest>, RepoError>;

    /// Bloquea la fila (`FOR UPDATE`) y la devuelve junto al umbral de su
    /// escrow — el Service decide en Rust si ya alcanzó el umbral, nunca en
    /// SQL, para no duplicar la lógica de negocio en dos lenguajes.
    async fn bloquear_pendiente_con_umbral(
        &self,
        id: Uuid,
        tx: &mut sqlx::PgConnection,
    ) -> Result<Option<(RecoveryRequest, i32)>, RepoError>;

    async fn guardar_aprobaciones(
        &self,
        id: Uuid,
        approvals: serde_json::Value,
        tx: &mut sqlx::PgConnection,
    ) -> Result<(), RepoError>;

    /// Marca `approved` + guarda el material re-sellado para el solicitante
    /// — sólo se llama una vez alcanzado el umbral.
    async fn marcar_aprobada(
        &self,
        id: Uuid,
        sealed_private_key_for_requester: &[u8],
        tx: &mut sqlx::PgConnection,
    ) -> Result<(), RepoError>;

    async fn marcar_completada(&self, id: Uuid) -> Result<bool, RepoError>;
}

#[allow(clippy::too_many_arguments)]
fn fila_a_request(
    id: Uuid,
    escrow_id: Uuid,
    requested_by: Option<Uuid>,
    status: String,
    approvals: serde_json::Value,
    requester_public_key_x25519: Vec<u8>,
    sealed_private_key_for_requester: Option<Vec<u8>>,
    created_at: time::OffsetDateTime,
) -> RecoveryRequest {
    RecoveryRequest {
        id,
        escrow_id,
        requested_by,
        status,
        approvals,
        requester_public_key_x25519,
        sealed_private_key_for_requester,
        created_at,
    }
}

#[derive(Clone)]
pub struct PgAccountRecoveryPolicyRepository {
    pub pool: sqlx::PgPool,
}

impl AccountRecoveryPolicyRepository for PgAccountRecoveryPolicyRepository {
    async fn obtener(&self) -> Result<AccountRecoveryPolicy, RepoError> {
        let fila = sqlx::query!(
            r#"select required, grace_period_days, default_approval_threshold
               from account_recovery_policy where organization_id = 1"#,
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(AccountRecoveryPolicy {
            required: fila.required,
            grace_period_days: fila.grace_period_days,
            default_approval_threshold: fila.default_approval_threshold,
        })
    }

    async fn actualizar(&self, policy: &AccountRecoveryPolicy) -> Result<(), RepoError> {
        sqlx::query!(
            r#"
            update account_recovery_policy set
                required = $1, grace_period_days = $2, default_approval_threshold = $3
            where organization_id = 1
            "#,
            policy.required,
            policy.grace_period_days,
            policy.default_approval_threshold,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct PgOrgRecoveryKeyRepository {
    pub pool: sqlx::PgPool,
}

impl OrgRecoveryKeyRepository for PgOrgRecoveryKeyRepository {
    async fn obtener_o_crear(
        &self,
        generar: impl FnOnce() -> (Vec<u8>, Vec<u8>, Vec<u8>),
    ) -> Result<OrgRecoveryKey, RepoError> {
        if let Some(fila) = sqlx::query!(
            r#"select id, public_key_x25519, encrypted_private_key, private_key_nonce
               from org_recovery_keys where id = 1"#,
        )
        .fetch_optional(&self.pool)
        .await?
        {
            return Ok(OrgRecoveryKey {
                id: fila.id,
                public_key_x25519: fila.public_key_x25519,
                encrypted_private_key: fila.encrypted_private_key,
                private_key_nonce: fila.private_key_nonce,
            });
        }

        let (publica, cifrada, nonce) = generar();
        let fila = sqlx::query!(
            r#"
            insert into org_recovery_keys (id, public_key_x25519, encrypted_private_key, private_key_nonce)
            values (1, $1, $2, $3)
            on conflict (id) do update set id = org_recovery_keys.id
            returning id, public_key_x25519, encrypted_private_key, private_key_nonce
            "#,
            publica,
            cifrada,
            nonce,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(OrgRecoveryKey {
            id: fila.id,
            public_key_x25519: fila.public_key_x25519,
            encrypted_private_key: fila.encrypted_private_key,
            private_key_nonce: fila.private_key_nonce,
        })
    }
}

#[derive(Clone)]
pub struct PgEscrowRepository {
    pub pool: sqlx::PgPool,
}

impl EscrowRepository for PgEscrowRepository {
    async fn upsert(
        &self,
        user_id: Uuid,
        sealed_private_key_for_org: &[u8],
        org_recovery_key_id: i32,
        approval_threshold: i32,
    ) -> Result<Escrow, RepoError> {
        let fila = sqlx::query!(
            r#"
            insert into account_recovery_escrow
                (user_id, sealed_private_key_for_org, org_recovery_key_id, approval_threshold)
            values ($1, $2, $3, $4)
            on conflict (user_id) do update set
                sealed_private_key_for_org = excluded.sealed_private_key_for_org,
                org_recovery_key_id = excluded.org_recovery_key_id,
                approval_threshold = excluded.approval_threshold
            returning id, user_id, sealed_private_key_for_org, org_recovery_key_id, approval_threshold, created_at
            "#,
            user_id,
            sealed_private_key_for_org,
            org_recovery_key_id,
            approval_threshold,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(Escrow {
            id: fila.id,
            user_id: fila.user_id,
            sealed_private_key_for_org: fila.sealed_private_key_for_org,
            org_recovery_key_id: fila.org_recovery_key_id,
            approval_threshold: fila.approval_threshold,
            created_at: fila.created_at,
        })
    }

    async fn buscar_por_usuario(&self, user_id: Uuid) -> Result<Option<Escrow>, RepoError> {
        let fila = sqlx::query!(
            r#"select id, user_id, sealed_private_key_for_org, org_recovery_key_id, approval_threshold, created_at
               from account_recovery_escrow where user_id = $1"#,
            user_id,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(fila.map(|f| Escrow {
            id: f.id,
            user_id: f.user_id,
            sealed_private_key_for_org: f.sealed_private_key_for_org,
            org_recovery_key_id: f.org_recovery_key_id,
            approval_threshold: f.approval_threshold,
            created_at: f.created_at,
        }))
    }

    async fn buscar(&self, id: Uuid) -> Result<Option<Escrow>, RepoError> {
        let fila = sqlx::query!(
            r#"select id, user_id, sealed_private_key_for_org, org_recovery_key_id, approval_threshold, created_at
               from account_recovery_escrow where id = $1"#,
            id,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(fila.map(|f| Escrow {
            id: f.id,
            user_id: f.user_id,
            sealed_private_key_for_org: f.sealed_private_key_for_org,
            org_recovery_key_id: f.org_recovery_key_id,
            approval_threshold: f.approval_threshold,
            created_at: f.created_at,
        }))
    }
}

#[derive(Clone)]
pub struct PgRecoveryRequestRepository {
    pub pool: sqlx::PgPool,
}

impl RecoveryRequestRepository for PgRecoveryRequestRepository {
    async fn crear(
        &self,
        escrow_id: Uuid,
        requested_by: Option<Uuid>,
        requester_public_key_x25519: &[u8],
    ) -> Result<RecoveryRequest, RepoError> {
        let fila = sqlx::query!(
            r#"
            insert into account_recovery_requests (escrow_id, requested_by, requester_public_key_x25519)
            values ($1, $2, $3)
            returning id, escrow_id, requested_by, status, approvals,
                      requester_public_key_x25519, sealed_private_key_for_requester, created_at
            "#,
            escrow_id,
            requested_by,
            requester_public_key_x25519,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(fila_a_request(
            fila.id,
            fila.escrow_id,
            fila.requested_by,
            fila.status,
            fila.approvals,
            fila.requester_public_key_x25519,
            fila.sealed_private_key_for_requester,
            fila.created_at,
        ))
    }

    async fn buscar(&self, id: Uuid) -> Result<Option<RecoveryRequest>, RepoError> {
        let fila = sqlx::query!(
            r#"
            select id, escrow_id, requested_by, status, approvals,
                   requester_public_key_x25519, sealed_private_key_for_requester, created_at
            from account_recovery_requests where id = $1
            "#,
            id,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(fila.map(|f| {
            fila_a_request(
                f.id,
                f.escrow_id,
                f.requested_by,
                f.status,
                f.approvals,
                f.requester_public_key_x25519,
                f.sealed_private_key_for_requester,
                f.created_at,
            )
        }))
    }

    async fn bloquear_pendiente_con_umbral(
        &self,
        id: Uuid,
        tx: &mut sqlx::PgConnection,
    ) -> Result<Option<(RecoveryRequest, i32)>, RepoError> {
        let fila = sqlx::query!(
            r#"
            select r.id, r.escrow_id, r.requested_by, r.status, r.approvals,
                   r.requester_public_key_x25519, r.sealed_private_key_for_requester, r.created_at,
                   e.approval_threshold
            from account_recovery_requests r
            join account_recovery_escrow e on e.id = r.escrow_id
            where r.id = $1 and r.status = 'pending'
            for update
            "#,
            id,
        )
        .fetch_optional(&mut *tx)
        .await?;

        Ok(fila.map(|f| {
            (
                fila_a_request(
                    f.id,
                    f.escrow_id,
                    f.requested_by,
                    f.status,
                    f.approvals,
                    f.requester_public_key_x25519,
                    f.sealed_private_key_for_requester,
                    f.created_at,
                ),
                f.approval_threshold,
            )
        }))
    }

    async fn guardar_aprobaciones(
        &self,
        id: Uuid,
        approvals: serde_json::Value,
        tx: &mut sqlx::PgConnection,
    ) -> Result<(), RepoError> {
        sqlx::query!(
            r#"update account_recovery_requests set approvals = $2 where id = $1"#,
            id,
            approvals,
        )
        .execute(&mut *tx)
        .await?;
        Ok(())
    }

    async fn marcar_aprobada(
        &self,
        id: Uuid,
        sealed_private_key_for_requester: &[u8],
        tx: &mut sqlx::PgConnection,
    ) -> Result<(), RepoError> {
        sqlx::query!(
            r#"
            update account_recovery_requests
            set status = 'approved', resolved_at = now(), sealed_private_key_for_requester = $2
            where id = $1
            "#,
            id,
            sealed_private_key_for_requester,
        )
        .execute(&mut *tx)
        .await?;
        Ok(())
    }

    async fn marcar_completada(&self, id: Uuid) -> Result<bool, RepoError> {
        let resultado = sqlx::query!(
            r#"update account_recovery_requests set status = 'completed'
               where id = $1 and status = 'approved'"#,
            id,
        )
        .execute(&self.pool)
        .await?;
        Ok(resultado.rows_affected() == 1)
    }
}
