// Autor: Athan Espinoza

#![allow(async_fn_in_trait)]

use crate::error::RepoError;

use super::models::SelfRegistrationPolicy;

pub trait SelfRegistrationPolicyRepository {
    async fn obtener(&self) -> Result<SelfRegistrationPolicy, RepoError>;
    async fn actualizar(&self, policy: &SelfRegistrationPolicy) -> Result<(), RepoError>;
}

#[derive(Clone)]
pub struct PgSelfRegistrationPolicyRepository {
    pub pool: sqlx::PgPool,
}

impl SelfRegistrationPolicyRepository for PgSelfRegistrationPolicyRepository {
    async fn obtener(&self) -> Result<SelfRegistrationPolicy, RepoError> {
        let fila = sqlx::query!(
            r#"select enabled, allowed_domains from self_registration_policy where organization_id = 1"#,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(SelfRegistrationPolicy { enabled: fila.enabled, allowed_domains: fila.allowed_domains })
    }

    async fn actualizar(&self, policy: &SelfRegistrationPolicy) -> Result<(), RepoError> {
        sqlx::query!(
            r#"update self_registration_policy set enabled = $1, allowed_domains = $2 where organization_id = 1"#,
            policy.enabled,
            &policy.allowed_domains,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
