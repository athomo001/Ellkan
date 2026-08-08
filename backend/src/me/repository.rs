// Autor: Athan Espinoza

#![allow(async_fn_in_trait)]

use uuid::Uuid;

use crate::error::RepoError;

use super::models::Preferencias;

pub trait PreferenciasRepository {
    async fn obtener(&self, user_id: Uuid) -> Result<Preferencias, RepoError>;
    async fn actualizar(&self, user_id: Uuid, p: &Preferencias) -> Result<(), RepoError>;
}

#[derive(Clone)]
pub struct PgPreferenciasRepository {
    pub pool: sqlx::PgPool,
}

impl PreferenciasRepository for PgPreferenciasRepository {
    async fn obtener(&self, user_id: Uuid) -> Result<Preferencias, RepoError> {
        let fila = sqlx::query!(
            r#"select locale, theme, clipboard_clear_minutes, auto_lock_minutes
               from users where id = $1"#,
            user_id,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(Preferencias {
            locale: fila.locale,
            theme: fila.theme,
            clipboard_clear_minutes: fila.clipboard_clear_minutes,
            auto_lock_minutes: fila.auto_lock_minutes,
        })
    }

    async fn actualizar(&self, user_id: Uuid, p: &Preferencias) -> Result<(), RepoError> {
        sqlx::query!(
            r#"update users set locale = $1, theme = $2, clipboard_clear_minutes = $3, auto_lock_minutes = $4
               where id = $5"#,
            p.locale,
            p.theme,
            p.clipboard_clear_minutes,
            p.auto_lock_minutes,
            user_id,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
