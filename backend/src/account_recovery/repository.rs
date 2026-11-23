// Autor: Athan Espinoza

#![allow(async_fn_in_trait)]

use uuid::Uuid;

use crate::error::RepoError;

use super::models::{
    AccountRecoveryPolicy, Custodia, CustodioPendiente, Escrow, MaterialParaCustodio, OrgRecoveryKey, RecoveryRequest, SolicitudPendiente,
};

pub trait AccountRecoveryPolicyRepository {
    async fn obtener(&self) -> Result<AccountRecoveryPolicy, RepoError>;
    async fn actualizar(&self, policy: &AccountRecoveryPolicy) -> Result<(), RepoError>;
}

/// QA-09: claves organizacionales de recuperación. La vigente es la de mayor
/// `id`; las anteriores siguen sirviendo a los escrows que no se re-sellaron.
pub trait OrgRecoveryKeyRepository {
    async fn vigente(&self) -> Result<Option<OrgRecoveryKey>, RepoError>;
    async fn buscar(&self, id: i32) -> Result<Option<OrgRecoveryKey>, RepoError>;
    /// Alta de una clave generada en el navegador de `creada_por`, con la
    /// privada ya sellada para cada custodio, en una sola transacción.
    async fn crear_de_cliente(&self, publica: &[u8], creada_por: Uuid, sobres: &[(Uuid, Vec<u8>)]) -> Result<i32, RepoError>;
    /// La privada de `key_id` sellada para `admin_id`.
    async fn sobre(&self, key_id: i32, admin_id: Uuid) -> Result<Option<Vec<u8>>, RepoError>;
    /// `false` si `admin_id` ya tenía su copia.
    async fn agregar_sobre(&self, key_id: i32, admin_id: Uuid, sellado: &[u8], sellado_por: Uuid) -> Result<bool, RepoError>;
    /// Admins de organización activos, con claves, sin copia de `key_id`
    /// (todos si `key_id` es `None`).
    async fn custodios_pendientes(&self, key_id: Option<i32>) -> Result<Vec<CustodioPendiente>, RepoError>;
    /// La X25519 de `user_id` si es admin de organización activo con claves.
    async fn x25519_de_admin(&self, user_id: Uuid) -> Result<Option<Vec<u8>>, RepoError>;
    /// Escrows sellados contra una clave del servidor.
    async fn escrows_en_servidor(&self) -> Result<i64, RepoError>;
    /// ¿Queda alguna clave del servidor sin purgar?
    async fn servidor_tiene_privada(&self) -> Result<bool, RepoError>;
    /// Borra la privada de toda clave del servidor y los escrows (con sus
    /// solicitudes) que seguían en ellas. Devuelve cuántos escrows se
    /// borraron.
    async fn purgar_servidor(&self) -> Result<i64, RepoError>;
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
    /// Crea la solicitud `unconfirmed`, con el hash del código enviado al
    /// email de la cuenta y vencimiento corto (`expires_at`). Vence antes
    /// cualquier otra `unconfirmed` del mismo escrow: sólo vale el último
    /// código pedido.
    async fn crear(
        &self,
        escrow_id: Uuid,
        requester_public_key_x25519: &[u8],
        confirmation_code_hash: &[u8],
        expires_at: time::OffsetDateTime,
    ) -> Result<RecoveryRequest, RepoError>;

    async fn buscar(&self, id: Uuid) -> Result<Option<RecoveryRequest>, RepoError>;

    /// Suma un intento fallido de confirmación; al llegar a `max_intentos`
    /// la solicitud queda `expired` y hay que pedir una nueva.
    async fn registrar_intento_fallido(&self, id: Uuid, max_intentos: i32) -> Result<(), RepoError>;

    /// `unconfirmed -> pending`: guarda el hash del token del solicitante y
    /// el vencimiento definitivo. Antes vence las solicitudes `pending`/
    /// `approved` de ese escrow que ya pasaron su `expires_at`, para que no
    /// bloqueen el índice de "una sola pendiente". `Ok(false)` si ya no
    /// estaba `unconfirmed` o venció; `Conflict` si el escrow ya tiene otra
    /// solicitud pendiente vigente.
    async fn confirmar(&self, id: Uuid, requester_token_hash: &[u8], expires_at: time::OffsetDateTime) -> Result<bool, RepoError>;

    /// Bloquea la fila (`FOR UPDATE`) y la devuelve junto al umbral de su
    /// escrow — el Service decide en Rust si ya alcanzó el umbral, nunca en
    /// SQL, para no duplicar la lógica de negocio en dos lenguajes. Sólo
    /// solicitudes `pending` y no vencidas.
    async fn bloquear_pendiente_con_umbral(
        &self,
        id: Uuid,
        tx: &mut sqlx::PgConnection,
    ) -> Result<Option<(RecoveryRequest, i32)>, RepoError>;

    async fn guardar_aprobaciones(&self, id: Uuid, approvals: serde_json::Value, tx: &mut sqlx::PgConnection) -> Result<(), RepoError>;

    /// Marca `approved` + guarda el material re-sellado para el solicitante
    /// — sólo se llama una vez alcanzado el umbral.
    async fn marcar_aprobada(
        &self,
        id: Uuid,
        sealed_private_key_for_requester: &[u8],
        tx: &mut sqlx::PgConnection,
    ) -> Result<(), RepoError>;

    /// QA-09: umbral alcanzado sobre una clave de cliente — falta que un
    /// custodio re-selle (`pending -> awaiting_custodian`).
    async fn marcar_esperando_custodio(&self, id: Uuid, tx: &mut sqlx::PgConnection) -> Result<(), RepoError>;

    /// QA-09: lo que el navegador de `custodio` necesita para re-sellar una
    /// solicitud `awaiting_custodian` vigente: `None` si no está en ese
    /// estado, venció, o `custodio` no tiene copia de la clave del escrow.
    async fn material_para_custodio(&self, id: Uuid, custodio: Uuid) -> Result<Option<MaterialParaCustodio>, RepoError>;

    /// QA-09: `awaiting_custodian -> approved` con el material que re-selló
    /// el custodio. `false` si ya no estaba en ese estado o venció.
    async fn marcar_ejecutada(&self, id: Uuid, sealed_private_key_for_requester: &[u8]) -> Result<bool, RepoError>;

    /// `approved -> completed`, sólo si no venció.
    async fn marcar_completada(&self, id: Uuid) -> Result<bool, RepoError>;

    /// 2026-08-11: mismo lock optimista que `marcar_completada` — sólo
    /// transiciona `pending`/`awaiting_custodian -> rejected`, nunca pisa
    /// una ya resuelta.
    async fn marcar_rechazada(&self, id: Uuid) -> Result<bool, RepoError>;

    /// `GET /admin/account-recovery/requests` — único modo de que un admin
    /// descubra que existe una solicitud pendiente (el id sólo lo conoce
    /// quien la creó). 2026-08-11: acotado por visibilidad — un admin de
    /// organización (`es_admin_org`) ve todas; un admin de grupo sólo ve las
    /// de usuarios que comparten alguno de `grupos_administrados` con él.
    /// Sólo `pending`/`awaiting_custodian` y no vencidas.
    async fn listar_pendientes_visibles(
        &self,
        es_admin_org: bool,
        grupos_administrados: &[Uuid],
    ) -> Result<Vec<SolicitudPendiente>, RepoError>;
}

/// Las queries repiten la lista de columnas literalmente porque `query!`
/// necesita el SQL completo en compilación.
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
    confirmation_code_hash: Option<Vec<u8>>,
    requester_token_hash: Option<Vec<u8>>,
    expires_at: time::OffsetDateTime,
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
        confirmation_code_hash,
        requester_token_hash,
        expires_at,
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

fn fila_a_clave(
    id: i32,
    public_key_x25519: Vec<u8>,
    encrypted_private_key: Option<Vec<u8>>,
    private_key_nonce: Option<Vec<u8>>,
    custody: &str,
    created_at: time::OffsetDateTime,
) -> OrgRecoveryKey {
    OrgRecoveryKey {
        id,
        public_key_x25519,
        encrypted_private_key,
        private_key_nonce,
        custodia: Custodia::desde_db(custody),
        created_at,
    }
}

impl OrgRecoveryKeyRepository for PgOrgRecoveryKeyRepository {
    async fn vigente(&self) -> Result<Option<OrgRecoveryKey>, RepoError> {
        let fila = sqlx::query!(
            r#"select id, public_key_x25519, encrypted_private_key, private_key_nonce, custody, created_at
               from org_recovery_keys order by id desc limit 1"#,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(fila.map(|f| fila_a_clave(f.id, f.public_key_x25519, f.encrypted_private_key, f.private_key_nonce, &f.custody, f.created_at)))
    }

    async fn buscar(&self, id: i32) -> Result<Option<OrgRecoveryKey>, RepoError> {
        let fila = sqlx::query!(
            r#"select id, public_key_x25519, encrypted_private_key, private_key_nonce, custody, created_at
               from org_recovery_keys where id = $1"#,
            id,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(fila.map(|f| fila_a_clave(f.id, f.public_key_x25519, f.encrypted_private_key, f.private_key_nonce, &f.custody, f.created_at)))
    }

    async fn crear_de_cliente(&self, publica: &[u8], creada_por: Uuid, sobres: &[(Uuid, Vec<u8>)]) -> Result<i32, RepoError> {
        let mut tx = self.pool.begin().await?;
        let id = sqlx::query_scalar!(
            r#"insert into org_recovery_keys (public_key_x25519, custody, created_by)
               values ($1, 'client', $2) returning id"#,
            publica,
            creada_por,
        )
        .fetch_one(&mut *tx)
        .await?;
        for (admin_id, sellado) in sobres {
            sqlx::query!(
                r#"insert into org_recovery_key_envelopes (org_recovery_key_id, admin_id, sealed_private_key, sealed_by)
                   values ($1, $2, $3, $4)"#,
                id,
                admin_id,
                sellado,
                creada_por,
            )
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(id)
    }

    async fn sobre(&self, key_id: i32, admin_id: Uuid) -> Result<Option<Vec<u8>>, RepoError> {
        Ok(sqlx::query_scalar!(
            r#"select sealed_private_key from org_recovery_key_envelopes
               where org_recovery_key_id = $1 and admin_id = $2"#,
            key_id,
            admin_id,
        )
        .fetch_optional(&self.pool)
        .await?)
    }

    async fn agregar_sobre(&self, key_id: i32, admin_id: Uuid, sellado: &[u8], sellado_por: Uuid) -> Result<bool, RepoError> {
        let resultado = sqlx::query!(
            r#"insert into org_recovery_key_envelopes (org_recovery_key_id, admin_id, sealed_private_key, sealed_by)
               values ($1, $2, $3, $4)
               on conflict (org_recovery_key_id, admin_id) do nothing"#,
            key_id,
            admin_id,
            sellado,
            sellado_por,
        )
        .execute(&self.pool)
        .await?;
        Ok(resultado.rows_affected() == 1)
    }

    async fn custodios_pendientes(&self, key_id: Option<i32>) -> Result<Vec<CustodioPendiente>, RepoError> {
        let filas = sqlx::query!(
            r#"
            select distinct u.id, u.email, u.display_name, uk.public_key_x25519
            from users u
            join role_permissions rp on rp.role_id = u.role_id and rp.permission = '*'
            join user_keys uk on uk.user_id = u.id and octet_length(uk.encrypted_private_key_blob) > 0
            where u.deleted_at is null
              and not exists (
                  select 1 from org_recovery_key_envelopes s
                  where s.org_recovery_key_id = $1 and s.admin_id = u.id
              )
            order by u.email
            "#,
            key_id,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(filas
            .into_iter()
            .map(|f| CustodioPendiente {
                user_id: f.id,
                email: f.email,
                display_name: f.display_name,
                public_key_x25519: f.public_key_x25519,
            })
            .collect())
    }

    async fn x25519_de_admin(&self, user_id: Uuid) -> Result<Option<Vec<u8>>, RepoError> {
        Ok(sqlx::query_scalar!(
            r#"
            select uk.public_key_x25519
            from users u
            join role_permissions rp on rp.role_id = u.role_id and rp.permission = '*'
            join user_keys uk on uk.user_id = u.id and octet_length(uk.encrypted_private_key_blob) > 0
            where u.id = $1 and u.deleted_at is null
            "#,
            user_id,
        )
        .fetch_optional(&self.pool)
        .await?)
    }

    async fn escrows_en_servidor(&self) -> Result<i64, RepoError> {
        Ok(sqlx::query_scalar!(
            r#"select count(*) as "n!" from account_recovery_escrow e
               join org_recovery_keys k on k.id = e.org_recovery_key_id
               where k.custody = 'server'"#,
        )
        .fetch_one(&self.pool)
        .await?)
    }

    async fn servidor_tiene_privada(&self) -> Result<bool, RepoError> {
        Ok(sqlx::query_scalar!(
            r#"select exists (select 1 from org_recovery_keys where custody = 'server' and purged_at is null) as "existe!""#,
        )
        .fetch_one(&self.pool)
        .await?)
    }

    async fn purgar_servidor(&self) -> Result<i64, RepoError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query!(
            r#"delete from account_recovery_requests where escrow_id in (
                   select e.id from account_recovery_escrow e
                   join org_recovery_keys k on k.id = e.org_recovery_key_id
                   where k.custody = 'server')"#,
        )
        .execute(&mut *tx)
        .await?;
        let borrados = sqlx::query!(
            r#"delete from account_recovery_escrow where org_recovery_key_id in (
                   select id from org_recovery_keys where custody = 'server')"#,
        )
        .execute(&mut *tx)
        .await?
        .rows_affected();
        sqlx::query!(
            r#"update org_recovery_keys
               set encrypted_private_key = null, private_key_nonce = null, purged_at = now()
               where custody = 'server' and purged_at is null"#,
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(borrados as i64)
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
        requester_public_key_x25519: &[u8],
        confirmation_code_hash: &[u8],
        expires_at: time::OffsetDateTime,
    ) -> Result<RecoveryRequest, RepoError> {
        let mut tx = self.pool.begin().await?;

        sqlx::query!(
            r#"update account_recovery_requests set status = 'expired', resolved_at = now()
               where escrow_id = $1 and status = 'unconfirmed'"#,
            escrow_id,
        )
        .execute(&mut *tx)
        .await?;

        let f = sqlx::query!(
            r#"
            insert into account_recovery_requests
                (escrow_id, requester_public_key_x25519, status, confirmation_code_hash, expires_at)
            values ($1, $2, 'unconfirmed', $3, $4)
            returning id, escrow_id, requested_by, status, approvals,
                      requester_public_key_x25519, sealed_private_key_for_requester, created_at,
                      confirmation_code_hash, requester_token_hash, expires_at
            "#,
            escrow_id,
            requester_public_key_x25519,
            confirmation_code_hash,
            expires_at,
        )
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(fila_a_request(
            f.id,
            f.escrow_id,
            f.requested_by,
            f.status,
            f.approvals,
            f.requester_public_key_x25519,
            f.sealed_private_key_for_requester,
            f.created_at,
            f.confirmation_code_hash,
            f.requester_token_hash,
            f.expires_at,
        ))
    }

    async fn buscar(&self, id: Uuid) -> Result<Option<RecoveryRequest>, RepoError> {
        let fila = sqlx::query!(
            r#"
            select id, escrow_id, requested_by, status, approvals,
                   requester_public_key_x25519, sealed_private_key_for_requester, created_at,
                   confirmation_code_hash, requester_token_hash, expires_at
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
                f.confirmation_code_hash,
                f.requester_token_hash,
                f.expires_at,
            )
        }))
    }

    async fn registrar_intento_fallido(&self, id: Uuid, max_intentos: i32) -> Result<(), RepoError> {
        sqlx::query!(
            r#"
            update account_recovery_requests
            set confirmation_failed_attempts = confirmation_failed_attempts + 1,
                status = case when confirmation_failed_attempts + 1 >= $2 then 'expired' else status end,
                resolved_at = case when confirmation_failed_attempts + 1 >= $2 then now() else resolved_at end
            where id = $1 and status = 'unconfirmed'
            "#,
            id,
            max_intentos,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn confirmar(&self, id: Uuid, requester_token_hash: &[u8], expires_at: time::OffsetDateTime) -> Result<bool, RepoError> {
        let mut tx = self.pool.begin().await?;

        sqlx::query!(
            r#"
            update account_recovery_requests set status = 'expired', resolved_at = now()
            where escrow_id = (select escrow_id from account_recovery_requests where id = $1)
              and status in ('pending', 'awaiting_custodian', 'approved')
              and expires_at <= now()
            "#,
            id,
        )
        .execute(&mut *tx)
        .await?;

        let resultado = sqlx::query!(
            r#"
            update account_recovery_requests
            set status = 'pending', requester_token_hash = $2, confirmation_code_hash = null, expires_at = $3
            where id = $1 and status = 'unconfirmed' and expires_at > now()
            "#,
            id,
            requester_token_hash,
            expires_at,
        )
        .execute(&mut *tx)
        .await
        // H-27: `account_recovery_requests_pendiente_unica_idx` (migración
        // 0044) rechaza una segunda solicitud pendiente para el mismo
        // escrow — mismo criterio ya usado en `emergency_access`.
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => RepoError::Conflict,
            _ => RepoError::Database(e),
        })?;

        tx.commit().await?;
        Ok(resultado.rows_affected() == 1)
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
                   r.confirmation_code_hash, r.requester_token_hash, r.expires_at,
                   e.approval_threshold
            from account_recovery_requests r
            join account_recovery_escrow e on e.id = r.escrow_id
            where r.id = $1 and r.status = 'pending' and r.expires_at > now()
            for update of r
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
                    f.confirmation_code_hash,
                    f.requester_token_hash,
                    f.expires_at,
                ),
                f.approval_threshold,
            )
        }))
    }

    async fn guardar_aprobaciones(&self, id: Uuid, approvals: serde_json::Value, tx: &mut sqlx::PgConnection) -> Result<(), RepoError> {
        sqlx::query!(r#"update account_recovery_requests set approvals = $2 where id = $1"#, id, approvals,)
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

    async fn marcar_esperando_custodio(&self, id: Uuid, tx: &mut sqlx::PgConnection) -> Result<(), RepoError> {
        sqlx::query!(r#"update account_recovery_requests set status = 'awaiting_custodian' where id = $1"#, id)
            .execute(&mut *tx)
            .await?;
        Ok(())
    }

    async fn material_para_custodio(&self, id: Uuid, custodio: Uuid) -> Result<Option<MaterialParaCustodio>, RepoError> {
        let fila = sqlx::query!(
            r#"
            select e.sealed_private_key_for_org, r.requester_public_key_x25519, e.org_recovery_key_id,
                   s.sealed_private_key as sobre
            from account_recovery_requests r
            join account_recovery_escrow e on e.id = r.escrow_id
            join org_recovery_key_envelopes s
              on s.org_recovery_key_id = e.org_recovery_key_id and s.admin_id = $2
            where r.id = $1 and r.status = 'awaiting_custodian' and r.expires_at > now()
            "#,
            id,
            custodio,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(fila.map(|f| MaterialParaCustodio {
            sealed_private_key_for_org: f.sealed_private_key_for_org,
            requester_public_key_x25519: f.requester_public_key_x25519,
            org_recovery_key_id: f.org_recovery_key_id,
            sobre: f.sobre,
        }))
    }

    async fn marcar_ejecutada(&self, id: Uuid, sealed_private_key_for_requester: &[u8]) -> Result<bool, RepoError> {
        let resultado = sqlx::query!(
            r#"
            update account_recovery_requests
            set status = 'approved', resolved_at = now(), sealed_private_key_for_requester = $2
            where id = $1 and status = 'awaiting_custodian' and expires_at > now()
            "#,
            id,
            sealed_private_key_for_requester,
        )
        .execute(&self.pool)
        .await?;
        Ok(resultado.rows_affected() == 1)
    }

    async fn marcar_completada(&self, id: Uuid) -> Result<bool, RepoError> {
        let resultado = sqlx::query!(
            r#"update account_recovery_requests set status = 'completed'
               where id = $1 and status = 'approved' and expires_at > now()"#,
            id,
        )
        .execute(&self.pool)
        .await?;
        Ok(resultado.rows_affected() == 1)
    }

    async fn marcar_rechazada(&self, id: Uuid) -> Result<bool, RepoError> {
        let resultado = sqlx::query!(
            r#"update account_recovery_requests set status = 'rejected', resolved_at = now()
               where id = $1 and status in ('pending', 'awaiting_custodian')"#,
            id,
        )
        .execute(&self.pool)
        .await?;
        Ok(resultado.rows_affected() == 1)
    }

    async fn listar_pendientes_visibles(
        &self,
        es_admin_org: bool,
        grupos_administrados: &[Uuid],
    ) -> Result<Vec<SolicitudPendiente>, RepoError> {
        let filas = sqlx::query!(
            r#"
            select r.id, u.email as target_email, r.status, r.approvals,
                   e.approval_threshold, r.created_at
            from account_recovery_requests r
            join account_recovery_escrow e on e.id = r.escrow_id
            join users u on u.id = e.user_id
            where r.status in ('pending', 'awaiting_custodian') and r.expires_at > now()
              and ($1 or exists (
                  select 1 from group_members gm
                  where gm.user_id = e.user_id and gm.group_id = any($2)
              ))
            order by r.created_at asc
            "#,
            es_admin_org,
            grupos_administrados,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(filas
            .into_iter()
            .map(|f| SolicitudPendiente {
                id: f.id,
                target_email: f.target_email,
                status: f.status,
                approvals: f.approvals,
                approval_threshold: f.approval_threshold,
                created_at: f.created_at,
            })
            .collect())
    }
}
