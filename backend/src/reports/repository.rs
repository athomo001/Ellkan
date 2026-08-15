// Autor: Athan Espinoza

#![allow(async_fn_in_trait)]

use uuid::Uuid;

use crate::error::RepoError;

use super::models::{FilaMfaCoverage, FilaPasswordExpirado, FilaRecursoSinRotar, FilaUsuarioInactivo};

pub trait ReportsRepository {
    async fn passwords_expired(
        &self,
        umbral_dias: i64,
        cursor: Option<Uuid>,
        limite: i64,
    ) -> Result<Vec<FilaPasswordExpirado>, RepoError>;

    async fn mfa_coverage(&self, cursor: Option<Uuid>, limite: i64) -> Result<Vec<FilaMfaCoverage>, RepoError>;

    async fn inactive_users(
        &self,
        umbral_dias: i64,
        cursor: Option<Uuid>,
        limite: i64,
    ) -> Result<Vec<FilaUsuarioInactivo>, RepoError>;

    async fn resources_never_rotated(
        &self,
        umbral_dias: i64,
        cursor: Option<Uuid>,
        limite: i64,
    ) -> Result<Vec<FilaRecursoSinRotar>, RepoError>;
}

#[derive(Clone)]
pub struct PgReportsRepository {
    pub pool: sqlx::PgPool,
}

impl ReportsRepository for PgReportsRepository {
    async fn passwords_expired(
        &self,
        umbral_dias: i64,
        cursor: Option<Uuid>,
        limite: i64,
    ) -> Result<Vec<FilaPasswordExpirado>, RepoError> {
        let filas = sqlx::query!(
            r#"
            select u.id as user_id, u.email, uk.created_at as passphrase_set_at
            from users u
            join user_keys uk on uk.user_id = u.id
            where u.deleted_at is null
              and uk.created_at < now() - make_interval(days => $1::int)
              and ($2::uuid is null or u.id < $2)
            order by u.id desc
            limit $3
            "#,
            umbral_dias as i32,
            cursor,
            limite,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(filas
            .into_iter()
            .map(|f| FilaPasswordExpirado { user_id: f.user_id, email: f.email, passphrase_set_at: f.passphrase_set_at })
            .collect())
    }

    async fn mfa_coverage(&self, cursor: Option<Uuid>, limite: i64) -> Result<Vec<FilaMfaCoverage>, RepoError> {
        let filas = sqlx::query!(
            r#"
            select u.id as user_id, u.email,
                   exists (
                       select 1 from user_totp_credentials t
                       where t.user_id = u.id and t.confirmed_at is not null
                   ) as "mfa_enabled!"
            from users u
            where u.deleted_at is null
              and ($1::uuid is null or u.id < $1)
            order by u.id desc
            limit $2
            "#,
            cursor,
            limite,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(filas.into_iter().map(|f| FilaMfaCoverage { user_id: f.user_id, email: f.email, mfa_enabled: f.mfa_enabled }).collect())
    }

    async fn inactive_users(
        &self,
        umbral_dias: i64,
        cursor: Option<Uuid>,
        limite: i64,
    ) -> Result<Vec<FilaUsuarioInactivo>, RepoError> {
        let filas = sqlx::query!(
            r#"
            select u.id as user_id, u.email, max(s.created_at) as last_login_at
            from users u
            left join sessions s on s.user_id = u.id
            where u.deleted_at is null
              and ($1::uuid is null or u.id < $1)
            group by u.id, u.email
            having max(s.created_at) is null or max(s.created_at) < now() - make_interval(days => $2::int)
            order by u.id desc
            limit $3
            "#,
            cursor,
            umbral_dias as i32,
            limite,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(filas
            .into_iter()
            .map(|f| FilaUsuarioInactivo { user_id: f.user_id, email: f.email, last_login_at: f.last_login_at })
            .collect())
    }

    async fn resources_never_rotated(
        &self,
        umbral_dias: i64,
        cursor: Option<Uuid>,
        limite: i64,
    ) -> Result<Vec<FilaRecursoSinRotar>, RepoError> {
        let filas = sqlx::query!(
            r#"
            select id as resource_id, created_by, created_at
            from resources
            where deleted_at is null
              and updated_at = created_at
              and created_at < now() - make_interval(days => $1::int)
              and ($2::uuid is null or id < $2)
            order by id desc
            limit $3
            "#,
            umbral_dias as i32,
            cursor,
            limite,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(filas
            .into_iter()
            .map(|f| FilaRecursoSinRotar { resource_id: f.resource_id, created_by: f.created_by, created_at: f.created_at })
            .collect())
    }
}
