// Autor: Athan Espinoza

#![allow(async_fn_in_trait)]

use crate::error::RepoError;

use super::models::SharingPolicy;

pub trait SharingPolicyRepository {
    async fn obtener(&self) -> Result<SharingPolicy, RepoError>;
    async fn actualizar(&self, policy: &SharingPolicy) -> Result<(), RepoError>;
}

#[derive(Clone)]
pub struct PgSharingPolicyRepository {
    pub pool: sqlx::PgPool,
}

impl SharingPolicyRepository for PgSharingPolicyRepository {
    async fn obtener(&self) -> Result<SharingPolicy, RepoError> {
        let fila = sqlx::query!(r#"select restrict_visibility_by_group from sharing_policy where organization_id = 1"#)
            .fetch_one(&self.pool)
            .await?;

        Ok(SharingPolicy { restrict_visibility_by_group: fila.restrict_visibility_by_group })
    }

    async fn actualizar(&self, policy: &SharingPolicy) -> Result<(), RepoError> {
        sqlx::query!(
            r#"update sharing_policy set restrict_visibility_by_group = $1 where organization_id = 1"#,
            policy.restrict_visibility_by_group,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
