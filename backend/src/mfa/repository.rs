// Autor: Athan Espinoza

#![allow(async_fn_in_trait)]

use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::RepoError;

use super::models::{MfaChallengeRow, MfaPolicy, TotpCredential};

pub trait MfaPolicyRepository {
    async fn obtener(&self) -> Result<MfaPolicy, RepoError>;

    /// `require_mfa_since` lo calcula el Service (transición false→true),
    /// no el Repository — acá sólo se persiste lo que ya se decidió.
    async fn actualizar(&self, policy: &MfaPolicy) -> Result<(), RepoError>;
}

pub trait TotpCredentialRepository {
    /// Da de baja (soft-delete) cualquier credential sin confirmar previo
    /// del usuario antes de crear uno nuevo — evita acumular secretos
    /// generados y nunca confirmados.
    async fn limpiar_pendientes(&self, user_id: Uuid) -> Result<(), RepoError>;

    async fn crear_pendiente(
        &self,
        user_id: Uuid,
        secret_ciphertext: &[u8],
        secret_nonce: &[u8],
    ) -> Result<TotpCredential, RepoError>;

    /// El credential sin confirmar más reciente del usuario — el que
    /// `confirmar_setup` intenta cerrar.
    async fn buscar_pendiente(&self, user_id: Uuid) -> Result<Option<TotpCredential>, RepoError>;

    /// El único credential confirmado y activo del usuario, si existe.
    async fn buscar_confirmado(&self, user_id: Uuid) -> Result<Option<TotpCredential>, RepoError>;

    async fn confirmar(&self, id: Uuid) -> Result<(), RepoError>;

    /// Soft-delete de cualquier credential confirmado previo — mantiene el
    /// invariante de "uno solo activo" cuando se confirma uno nuevo.
    async fn revocar_confirmados_de(&self, user_id: Uuid) -> Result<(), RepoError>;
}

pub trait MfaChallengeRepository {
    async fn crear(
        &self,
        user_id: Uuid,
        session_hash: &[u8],
        expires_at: OffsetDateTime,
    ) -> Result<(), RepoError>;

    /// Todos los desafíos pendientes (no consumidos, no vencidos) del
    /// usuario — normalmente 0 o 1, pero nunca se asume unicidad: el caller
    /// compara `session_hash` en tiempo constante contra cada uno hasta
    /// encontrar el que corresponde a la sesión parcial actual.
    async fn listar_pendientes(&self, user_id: Uuid) -> Result<Vec<MfaChallengeRow>, RepoError>;

    async fn consumir(&self, id: Uuid) -> Result<(), RepoError>;
}

#[derive(Clone)]
pub struct PgMfaPolicyRepository {
    pub pool: sqlx::PgPool,
}

impl MfaPolicyRepository for PgMfaPolicyRepository {
    async fn obtener(&self) -> Result<MfaPolicy, RepoError> {
        let fila = sqlx::query!(
            r#"select require_mfa, allowed_methods, grace_period_days, require_mfa_since
               from mfa_policy where organization_id = 1"#,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(MfaPolicy {
            require_mfa: fila.require_mfa,
            allowed_methods: fila.allowed_methods,
            grace_period_days: fila.grace_period_days,
            require_mfa_since: fila.require_mfa_since,
        })
    }

    async fn actualizar(&self, policy: &MfaPolicy) -> Result<(), RepoError> {
        sqlx::query!(
            r#"update mfa_policy set require_mfa = $1, allowed_methods = $2,
               grace_period_days = $3, require_mfa_since = $4
               where organization_id = 1"#,
            policy.require_mfa,
            &policy.allowed_methods,
            policy.grace_period_days,
            policy.require_mfa_since,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct PgTotpCredentialRepository {
    pub pool: sqlx::PgPool,
}

impl TotpCredentialRepository for PgTotpCredentialRepository {
    async fn limpiar_pendientes(&self, user_id: Uuid) -> Result<(), RepoError> {
        sqlx::query!(
            r#"update user_totp_credentials set deleted_at = now()
               where user_id = $1 and confirmed_at is null and deleted_at is null"#,
            user_id,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn crear_pendiente(
        &self,
        user_id: Uuid,
        secret_ciphertext: &[u8],
        secret_nonce: &[u8],
    ) -> Result<TotpCredential, RepoError> {
        let fila = sqlx::query!(
            r#"insert into user_totp_credentials (user_id, secret_ciphertext, secret_nonce)
               values ($1, $2, $3)
               returning id, user_id, secret_ciphertext, secret_nonce, confirmed_at"#,
            user_id,
            secret_ciphertext,
            secret_nonce,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(TotpCredential {
            id: fila.id,
            user_id: fila.user_id,
            secret_ciphertext: fila.secret_ciphertext,
            secret_nonce: fila.secret_nonce,
            confirmed_at: fila.confirmed_at,
        })
    }

    async fn buscar_pendiente(&self, user_id: Uuid) -> Result<Option<TotpCredential>, RepoError> {
        let fila = sqlx::query!(
            r#"select id, user_id, secret_ciphertext, secret_nonce, confirmed_at
               from user_totp_credentials
               where user_id = $1 and confirmed_at is null and deleted_at is null
               order by created_at desc limit 1"#,
            user_id,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(fila.map(|f| TotpCredential {
            id: f.id,
            user_id: f.user_id,
            secret_ciphertext: f.secret_ciphertext,
            secret_nonce: f.secret_nonce,
            confirmed_at: f.confirmed_at,
        }))
    }

    async fn buscar_confirmado(&self, user_id: Uuid) -> Result<Option<TotpCredential>, RepoError> {
        let fila = sqlx::query!(
            r#"select id, user_id, secret_ciphertext, secret_nonce, confirmed_at
               from user_totp_credentials
               where user_id = $1 and confirmed_at is not null and deleted_at is null"#,
            user_id,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(fila.map(|f| TotpCredential {
            id: f.id,
            user_id: f.user_id,
            secret_ciphertext: f.secret_ciphertext,
            secret_nonce: f.secret_nonce,
            confirmed_at: f.confirmed_at,
        }))
    }

    async fn confirmar(&self, id: Uuid) -> Result<(), RepoError> {
        sqlx::query!(r#"update user_totp_credentials set confirmed_at = now() where id = $1"#, id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn revocar_confirmados_de(&self, user_id: Uuid) -> Result<(), RepoError> {
        sqlx::query!(
            r#"update user_totp_credentials set deleted_at = now()
               where user_id = $1 and confirmed_at is not null and deleted_at is null"#,
            user_id,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct PgMfaChallengeRepository {
    pub pool: sqlx::PgPool,
}

impl MfaChallengeRepository for PgMfaChallengeRepository {
    async fn crear(
        &self,
        user_id: Uuid,
        session_hash: &[u8],
        expires_at: OffsetDateTime,
    ) -> Result<(), RepoError> {
        sqlx::query!(
            r#"insert into mfa_challenges (user_id, method, session_hash, expires_at)
               values ($1, 'totp', $2, $3)"#,
            user_id,
            session_hash,
            expires_at,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn listar_pendientes(&self, user_id: Uuid) -> Result<Vec<MfaChallengeRow>, RepoError> {
        let filas = sqlx::query!(
            r#"select id, user_id, session_hash from mfa_challenges
               where user_id = $1 and consumed_at is null and expires_at > now()"#,
            user_id,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(filas
            .into_iter()
            .map(|f| MfaChallengeRow { id: f.id, user_id: f.user_id, session_hash: f.session_hash })
            .collect())
    }

    async fn consumir(&self, id: Uuid) -> Result<(), RepoError> {
        sqlx::query!(r#"update mfa_challenges set consumed_at = now() where id = $1"#, id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
