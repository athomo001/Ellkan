// Autor: Athan Espinoza

#![allow(async_fn_in_trait)]

use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::RepoError;

use super::models::{LoginState, SsoConfig};

pub trait SsoConfigRepository {
    async fn obtener(&self) -> Result<SsoConfig, RepoError>;
    async fn actualizar(&self, config: &SsoConfig) -> Result<(), RepoError>;
}

pub trait SsoIdentityRepository {
    async fn buscar_user_id_por_identidad(&self, provider: &str, provider_user_id: &str) -> Result<Option<Uuid>, RepoError>;

    async fn vincular(
        &self,
        user_id: Uuid,
        provider: &str,
        provider_user_id: &str,
        metadata: serde_json::Value,
    ) -> Result<(), RepoError>;
}

pub trait LoginStateRepository {
    async fn crear(&self, state: &str, nonce: &str, pkce_verifier: &str, expires_at: OffsetDateTime) -> Result<(), RepoError>;

    /// Consume (marca usado) un `state` pendiente — devuelve `None` si no
    /// existía, ya estaba consumido, o venció (un `state` reutilizado o
    /// falsificado no debe validar nunca, sea cual sea el motivo).
    async fn consumir(&self, state: &str) -> Result<Option<LoginState>, RepoError>;
}

#[derive(Clone)]
pub struct PgSsoConfigRepository {
    pub pool: sqlx::PgPool,
}

impl SsoConfigRepository for PgSsoConfigRepository {
    async fn obtener(&self) -> Result<SsoConfig, RepoError> {
        let fila = sqlx::query!(
            r#"select issuer_url, client_id, jit_provisioning_enabled from sso_config where organization_id = 1"#,
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(SsoConfig {
            issuer_url: fila.issuer_url,
            client_id: fila.client_id,
            jit_provisioning_enabled: fila.jit_provisioning_enabled,
        })
    }

    async fn actualizar(&self, config: &SsoConfig) -> Result<(), RepoError> {
        sqlx::query!(
            r#"
            update sso_config set issuer_url = $1, client_id = $2, jit_provisioning_enabled = $3
            where organization_id = 1
            "#,
            config.issuer_url,
            config.client_id,
            config.jit_provisioning_enabled,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct PgSsoIdentityRepository {
    pub pool: sqlx::PgPool,
}

impl SsoIdentityRepository for PgSsoIdentityRepository {
    async fn buscar_user_id_por_identidad(&self, provider: &str, provider_user_id: &str) -> Result<Option<Uuid>, RepoError> {
        let fila = sqlx::query!(
            r#"select user_id from sso_identities where provider = $1 and provider_user_id = $2"#,
            provider,
            provider_user_id,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(fila.map(|f| f.user_id))
    }

    async fn vincular(
        &self,
        user_id: Uuid,
        provider: &str,
        provider_user_id: &str,
        metadata: serde_json::Value,
    ) -> Result<(), RepoError> {
        sqlx::query!(
            r#"
            insert into sso_identities (user_id, provider, provider_user_id, provider_metadata)
            values ($1, $2, $3, $4)
            on conflict (provider, provider_user_id) do nothing
            "#,
            user_id,
            provider,
            provider_user_id,
            metadata,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct PgLoginStateRepository {
    pub pool: sqlx::PgPool,
}

impl LoginStateRepository for PgLoginStateRepository {
    async fn crear(&self, state: &str, nonce: &str, pkce_verifier: &str, expires_at: OffsetDateTime) -> Result<(), RepoError> {
        sqlx::query!(
            r#"insert into sso_login_state (state, nonce, pkce_verifier, expires_at) values ($1, $2, $3, $4)"#,
            state,
            nonce,
            pkce_verifier,
            expires_at,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn consumir(&self, state: &str) -> Result<Option<LoginState>, RepoError> {
        let fila = sqlx::query!(
            r#"
            update sso_login_state set consumed_at = now()
            where state = $1 and consumed_at is null and expires_at > now()
            returning state, nonce, pkce_verifier, expires_at
            "#,
            state,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(fila.map(|f| LoginState {
            state: f.state,
            nonce: f.nonce,
            pkce_verifier: f.pkce_verifier,
            expires_at: f.expires_at,
        }))
    }
}
