// Autor: Athan Espinoza

//! Avatar del único usuario local (`avatar_local`, una sola fila). Ignora el
//! `user_id` a propósito: la fila tiene que sobrevivir a `reemplazar_identidad`
//! (ver la migración `0010_avatar.sql`), y en este modo hay un solo usuario.

use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use crate::error::RepoError;
use crate::me::models::Avatar;
use crate::me::repository::AvatarRepository;

#[derive(Clone)]
pub struct SqliteAvatarRepository {
    pub pool: SqlitePool,
}

impl AvatarRepository for SqliteAvatarRepository {
    async fn obtener(&self, _user_id: Uuid) -> Result<Option<Avatar>, RepoError> {
        let fila = sqlx::query("select bytes, content_type from avatar_local where id = 1").fetch_optional(&self.pool).await?;
        Ok(fila.map(|f| Avatar { bytes: f.get("bytes"), content_type: f.get("content_type") }))
    }

    async fn actualizar(&self, _user_id: Uuid, avatar: &Avatar) -> Result<(), RepoError> {
        sqlx::query(
            "insert into avatar_local (id, bytes, content_type) values (1, ?1, ?2) \
             on conflict (id) do update set bytes = excluded.bytes, content_type = excluded.content_type",
        )
        .bind(&avatar.bytes)
        .bind(&avatar.content_type)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn eliminar(&self, _user_id: Uuid) -> Result<(), RepoError> {
        sqlx::query("delete from avatar_local where id = 1").execute(&self.pool).await?;
        Ok(())
    }
}
