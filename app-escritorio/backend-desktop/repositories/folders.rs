// Autor: Athan Espinoza

//! Segunda implementación (SQLite, modo escritorio) de `FolderRepository`/
//! `FolderItemRepository` — mismo modelo que la versión Postgres
//! (`backend/src/folders/repository.rs`): `folders` sólo guarda el id
//! compartido entre vistas, el nombre cifrado vive en `folder_items`
//! por-usuario. Sin `permissions` (spec/13 §5): compartir una carpeta con
//! otro usuario/grupo no aplica en este modo — esos endpoints simplemente no
//! se montan en `desktop/router.rs`, este repository sólo cubre lo que sí
//! aplica (crear/reposicionar/anidar la propia bóveda).

use std::collections::HashMap;

use sqlx::{Row, SqlitePool};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::desktop::sqlite_util::{fmt_dt, parse_uuid};
use crate::error::RepoError;

use crate::folders::models::{Folder, NodoDeArbol};
use crate::folders::repository::{FolderItemRepository, FolderRepository};

#[derive(Clone)]
pub struct SqliteFolderRepository {
    pub pool: SqlitePool,
}

impl FolderRepository for SqliteFolderRepository {
    async fn crear(&self, id: Uuid) -> Result<Folder, RepoError> {
        sqlx::query("insert into folders (id) values (?1)").bind(id.to_string()).execute(&self.pool).await?;
        Ok(Folder { id })
    }

    async fn buscar(&self, id: Uuid) -> Result<Option<Folder>, RepoError> {
        let fila = sqlx::query("select id from folders where id = ?1 and deleted_at is null")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        fila.as_ref()
            .map(|f| -> Result<Folder, RepoError> { Ok(Folder { id: parse_uuid(f.try_get::<String, _>("id")?.as_str())? }) })
            .transpose()
    }

    async fn ancestros_inclusive(&self, user_id: Uuid, folder_id: Uuid) -> Result<Vec<Uuid>, RepoError> {
        let filas = sqlx::query(
            "with recursive ancestros(id, parent) as ( \
                select child_folder_id, folder_id from folder_items \
                where user_id = ?1 and child_folder_id = ?2 \
                union all \
                select fi.child_folder_id, fi.folder_id from folder_items fi \
                join ancestros a on fi.child_folder_id = a.parent and fi.user_id = ?1 \
             ) select id from ancestros",
        )
        .bind(user_id.to_string())
        .bind(folder_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        filas.iter().map(|f| parse_uuid(f.try_get::<String, _>("id")?.as_str())).collect()
    }

    async fn profundidad(&self, user_id: Uuid, folder_id: Uuid) -> Result<i32, RepoError> {
        Ok(self.ancestros_inclusive(user_id, folder_id).await?.len() as i32)
    }

    async fn descendientes_de(&self, user_id: Uuid, folder_id: Uuid) -> Result<Vec<Uuid>, RepoError> {
        let filas = sqlx::query(
            "with recursive descendientes(id) as ( \
                select child_folder_id from folder_items \
                where user_id = ?1 and folder_id = ?2 and child_folder_id is not null \
                union all \
                select fi.child_folder_id from folder_items fi \
                join descendientes d on fi.folder_id = d.id \
                where fi.user_id = ?1 and fi.child_folder_id is not null \
             ) select id from descendientes",
        )
        .bind(user_id.to_string())
        .bind(folder_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        filas.iter().map(|f| parse_uuid(f.try_get::<String, _>("id")?.as_str())).collect()
    }

    async fn marcar_eliminada(&self, id: Uuid) -> Result<bool, RepoError> {
        let resultado = sqlx::query("update folders set deleted_at = ?2 where id = ?1 and deleted_at is null")
            .bind(id.to_string())
            .bind(fmt_dt(OffsetDateTime::now_utc()))
            .execute(&self.pool)
            .await?;
        Ok(resultado.rows_affected() > 0)
    }

    async fn ids_eliminadas_desde(&self, desde: OffsetDateTime) -> Result<Vec<Uuid>, RepoError> {
        let filas = sqlx::query("select id from folders where deleted_at is not null and deleted_at > ?1")
            .bind(fmt_dt(desde))
            .fetch_all(&self.pool)
            .await?;
        filas.iter().map(|f| parse_uuid(f.try_get::<String, _>("id")?.as_str())).collect()
    }
}

#[derive(Clone)]
pub struct SqliteFolderItemRepository {
    pub pool: SqlitePool,
}

impl FolderItemRepository for SqliteFolderItemRepository {
    async fn insertar_carpeta(
        &self,
        user_id: Uuid,
        child_folder_id: Uuid,
        parent_folder_id: Option<Uuid>,
        name_ciphertext: &[u8],
        name_nonce: &[u8],
    ) -> Result<(), RepoError> {
        sqlx::query(
            "insert into folder_items (id, folder_id, child_folder_id, user_id, name_ciphertext, name_nonce, updated_at) \
             values (?1,?2,?3,?4,?5,?6,?7) \
             on conflict (user_id, child_folder_id) do update set \
                folder_id = excluded.folder_id, \
                name_ciphertext = excluded.name_ciphertext, \
                name_nonce = excluded.name_nonce, \
                updated_at = excluded.updated_at",
        )
        .bind(Uuid::now_v7().to_string())
        .bind(parent_folder_id.map(|u| u.to_string()))
        .bind(child_folder_id.to_string())
        .bind(user_id.to_string())
        .bind(name_ciphertext)
        .bind(name_nonce)
        .bind(fmt_dt(OffsetDateTime::now_utc()))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn reposicionar_carpeta(
        &self,
        user_id: Uuid,
        child_folder_id: Uuid,
        parent_folder_id: Option<Uuid>,
    ) -> Result<(), RepoError> {
        sqlx::query("update folder_items set folder_id = ?1, updated_at = ?4 where user_id = ?2 and child_folder_id = ?3")
            .bind(parent_folder_id.map(|u| u.to_string()))
            .bind(user_id.to_string())
            .bind(child_folder_id.to_string())
            .bind(fmt_dt(OffsetDateTime::now_utc()))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn tiene_en_su_arbol(&self, user_id: Uuid, child_folder_id: Uuid) -> Result<bool, RepoError> {
        let fila = sqlx::query("select 1 as x from folder_items where user_id = ?1 and child_folder_id = ?2")
            .bind(user_id.to_string())
            .bind(child_folder_id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        Ok(fila.is_some())
    }

    async fn arbol_de(&self, user_id: Uuid) -> Result<Vec<NodoDeArbol>, RepoError> {
        let filas = sqlx::query(
            "select fi.child_folder_id as folder_id, fi.folder_id as parent_folder_id, \
                    fi.name_ciphertext as name_ciphertext, fi.name_nonce as name_nonce \
             from folder_items fi \
             join folders f on f.id = fi.child_folder_id \
             where fi.user_id = ?1 and f.deleted_at is null \
             order by f.id",
        )
        .bind(user_id.to_string())
        .fetch_all(&self.pool)
        .await?;

        filas
            .iter()
            .map(|f| -> Result<NodoDeArbol, RepoError> {
                Ok(NodoDeArbol {
                    folder_id: parse_uuid(f.try_get::<String, _>("folder_id")?.as_str())?,
                    parent_folder_id: f.try_get::<Option<String>, _>("parent_folder_id")?.map(|s| parse_uuid(&s)).transpose()?,
                    name_ciphertext: f.try_get("name_ciphertext")?,
                    name_nonce: f.try_get("name_nonce")?,
                })
            })
            .collect()
    }

    async fn posicionar_recurso(
        &self,
        user_id: Uuid,
        resource_id: Uuid,
        parent_folder_id: Option<Uuid>,
    ) -> Result<(), RepoError> {
        sqlx::query(
            "insert into folder_items (id, folder_id, resource_id, user_id, updated_at) values (?1,?2,?3,?4,?5) \
             on conflict (user_id, resource_id) do update set folder_id = excluded.folder_id, updated_at = excluded.updated_at",
        )
        .bind(Uuid::now_v7().to_string())
        .bind(parent_folder_id.map(|u| u.to_string()))
        .bind(resource_id.to_string())
        .bind(user_id.to_string())
        .bind(fmt_dt(OffsetDateTime::now_utc()))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn posiciones_de_recursos(&self, user_id: Uuid) -> Result<HashMap<Uuid, Uuid>, RepoError> {
        let filas = sqlx::query(
            "select resource_id, folder_id from folder_items \
             where user_id = ?1 and resource_id is not null and folder_id is not null",
        )
        .bind(user_id.to_string())
        .fetch_all(&self.pool)
        .await?;

        filas
            .iter()
            .map(|f| -> Result<(Uuid, Uuid), RepoError> {
                Ok((
                    parse_uuid(f.try_get::<String, _>("resource_id")?.as_str())?,
                    parse_uuid(f.try_get::<String, _>("folder_id")?.as_str())?,
                ))
            })
            .collect()
    }

    async fn carpetas_de_recurso(&self, resource_id: Uuid) -> Result<Vec<Uuid>, RepoError> {
        let filas = sqlx::query("select distinct folder_id from folder_items where resource_id = ?1 and folder_id is not null")
            .bind(resource_id.to_string())
            .fetch_all(&self.pool)
            .await?;
        filas.iter().map(|f| parse_uuid(f.try_get::<String, _>("folder_id")?.as_str())).collect()
    }

    async fn tiene_hijos(&self, folder_id: Uuid) -> Result<bool, RepoError> {
        let fila = sqlx::query("select 1 as x from folder_items where folder_id = ?1 limit 1")
            .bind(folder_id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        Ok(fila.is_some())
    }

    async fn quitar_de_todos_los_arboles(&self, folder_id: Uuid) -> Result<(), RepoError> {
        sqlx::query("delete from folder_items where child_folder_id = ?1").bind(folder_id.to_string()).execute(&self.pool).await?;
        Ok(())
    }

    async fn cambios_desde(&self, user_id: Uuid, desde: OffsetDateTime) -> Result<Vec<NodoDeArbol>, RepoError> {
        let filas = sqlx::query(
            "select fi.child_folder_id as folder_id, fi.folder_id as parent_folder_id, \
                    fi.name_ciphertext as name_ciphertext, fi.name_nonce as name_nonce \
             from folder_items fi \
             join folders f on f.id = fi.child_folder_id \
             where fi.user_id = ?1 and f.deleted_at is null and fi.updated_at > ?2 \
             order by f.id",
        )
        .bind(user_id.to_string())
        .bind(fmt_dt(desde))
        .fetch_all(&self.pool)
        .await?;

        filas
            .iter()
            .map(|f| -> Result<NodoDeArbol, RepoError> {
                Ok(NodoDeArbol {
                    folder_id: parse_uuid(f.try_get::<String, _>("folder_id")?.as_str())?,
                    parent_folder_id: f.try_get::<Option<String>, _>("parent_folder_id")?.map(|s| parse_uuid(&s)).transpose()?,
                    name_ciphertext: f.try_get("name_ciphertext")?,
                    name_nonce: f.try_get("name_nonce")?,
                })
            })
            .collect()
    }

    async fn posiciones_de_recursos_cambiadas_desde(&self, user_id: Uuid, desde: OffsetDateTime) -> Result<HashMap<Uuid, Uuid>, RepoError> {
        let filas = sqlx::query(
            "select resource_id, folder_id from folder_items \
             where user_id = ?1 and resource_id is not null and folder_id is not null and updated_at > ?2",
        )
        .bind(user_id.to_string())
        .bind(fmt_dt(desde))
        .fetch_all(&self.pool)
        .await?;

        filas
            .iter()
            .map(|f| -> Result<(Uuid, Uuid), RepoError> {
                Ok((
                    parse_uuid(f.try_get::<String, _>("resource_id")?.as_str())?,
                    parse_uuid(f.try_get::<String, _>("folder_id")?.as_str())?,
                ))
            })
            .collect()
    }
}
