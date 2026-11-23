// Autor: Athan Espinoza

#![allow(async_fn_in_trait)]

use crate::error::RepoError;

use super::models::{EstadoAviso, UltimaVersion};

pub trait UpdateCheckRepository {
    async fn obtener(&self) -> Result<EstadoAviso, RepoError>;
    async fn fijar_habilitado(&self, enabled: bool) -> Result<(), RepoError>;
    async fn guardar_resultado(&self, ultima: &UltimaVersion) -> Result<(), RepoError>;
}

#[derive(Clone)]
pub struct PgUpdateCheckRepository {
    pub pool: sqlx::PgPool,
}

impl UpdateCheckRepository for PgUpdateCheckRepository {
    async fn obtener(&self) -> Result<EstadoAviso, RepoError> {
        let fila = sqlx::query!(r#"select enabled, latest_version, release_url, checked_at from update_check where id"#)
            .fetch_one(&self.pool)
            .await?;
        Ok(EstadoAviso {
            enabled: fila.enabled,
            latest_version: fila.latest_version,
            release_url: fila.release_url,
            checked_at: fila.checked_at,
        })
    }

    async fn fijar_habilitado(&self, enabled: bool) -> Result<(), RepoError> {
        sqlx::query!(r#"update update_check set enabled = $1, updated_at = now() where id"#, enabled)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn guardar_resultado(&self, ultima: &UltimaVersion) -> Result<(), RepoError> {
        sqlx::query!(
            r#"update update_check set latest_version = $1, release_url = $2, checked_at = now() where id"#,
            ultima.version,
            ultima.url,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
