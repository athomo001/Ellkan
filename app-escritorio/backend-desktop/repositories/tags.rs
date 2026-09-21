// Autor: Athan Espinoza

//! Segunda implementación (SQLite, modo escritorio) de `TagRepository` —
//! `recursos_visibles_con_tag` no tiene tabla `permissions` que consultar en
//! este modo (spec/13 §5): "visible para el viewer" colapsa a "el viewer es
//! el dueño del recurso" (`resources.created_by`), mismo criterio que
//! `SqlitePermissionRepository::es_dueno` en `resources.rs`.

use sqlx::{Row, SqlitePool};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::desktop::sqlite_util::{fmt_dt, parse_uuid};
use crate::error::RepoError;

use crate::tags::models::Tag;
use crate::tags::repository::TagRepository;

fn fila_a_tag(row: &sqlx::sqlite::SqliteRow) -> Result<Tag, RepoError> {
    Ok(Tag {
        id: parse_uuid(row.try_get::<String, _>("id")?.as_str())?,
        name: row.try_get("name")?,
        is_shared: row.try_get("is_shared")?,
        created_by: row.try_get::<Option<String>, _>("created_by")?.map(|s| parse_uuid(&s)).transpose()?,
    })
}

#[derive(Clone)]
pub struct SqliteTagRepository {
    pub pool: SqlitePool,
}

impl TagRepository for SqliteTagRepository {
    async fn crear(&self, id: Uuid, name: &str, is_shared: bool, created_by: Uuid) -> Result<Tag, RepoError> {
        sqlx::query("insert into tags (id, name, is_shared, created_by) values (?1,?2,?3,?4)")
            .bind(id.to_string())
            .bind(name)
            .bind(is_shared)
            .bind(created_by.to_string())
            .execute(&self.pool)
            .await?;
        Ok(Tag { id, name: name.to_string(), is_shared, created_by: Some(created_by) })
    }

    async fn buscar(&self, id: Uuid) -> Result<Option<Tag>, RepoError> {
        let fila = sqlx::query("select id, name, is_shared, created_by from tags where id = ?1 and deleted_at is null")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        fila.as_ref().map(fila_a_tag).transpose()
    }

    async fn listar_disponibles_para(&self, viewer_id: Uuid) -> Result<Vec<Tag>, RepoError> {
        let filas = sqlx::query(
            "select id, name, is_shared, created_by from tags \
             where deleted_at is null and (is_shared or created_by = ?1) order by name",
        )
        .bind(viewer_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        filas.iter().map(fila_a_tag).collect()
    }

    async fn aplicar(&self, resource_id: Uuid, tag_id: Uuid) -> Result<(), RepoError> {
        sqlx::query("insert into resource_tags (resource_id, tag_id) values (?1,?2) on conflict do nothing")
            .bind(resource_id.to_string())
            .bind(tag_id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn quitar(&self, resource_id: Uuid, tag_id: Uuid) -> Result<(), RepoError> {
        sqlx::query("delete from resource_tags where resource_id = ?1 and tag_id = ?2")
            .bind(resource_id.to_string())
            .bind(tag_id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn recursos_visibles_con_tag(&self, viewer_id: Uuid, tag_id: Uuid) -> Result<Vec<Uuid>, RepoError> {
        let filas = sqlx::query(
            "select distinct rt.resource_id from resource_tags rt \
             join resources r on r.id = rt.resource_id and r.deleted_at is null \
             where rt.tag_id = ?1 and r.created_by = ?2",
        )
        .bind(tag_id.to_string())
        .bind(viewer_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        filas.iter().map(|f| parse_uuid(f.try_get::<String, _>("resource_id")?.as_str())).collect()
    }

    async fn eliminar(&self, id: Uuid) -> Result<bool, RepoError> {
        let ahora = fmt_dt(OffsetDateTime::now_utc());
        let resultado = sqlx::query("update tags set deleted_at = ?2, updated_at = ?2 where id = ?1 and deleted_at is null")
            .bind(id.to_string())
            .bind(ahora)
            .execute(&self.pool)
            .await?;
        Ok(resultado.rows_affected() > 0)
    }

    async fn cambios_desde(&self, viewer_id: Uuid, desde: OffsetDateTime) -> Result<Vec<Tag>, RepoError> {
        let filas = sqlx::query(
            "select id, name, is_shared, created_by from tags \
             where deleted_at is null and (is_shared or created_by = ?1) and updated_at > ?2 order by name",
        )
        .bind(viewer_id.to_string())
        .bind(fmt_dt(desde))
        .fetch_all(&self.pool)
        .await?;
        filas.iter().map(fila_a_tag).collect()
    }

    async fn ids_eliminados_desde(&self, viewer_id: Uuid, desde: OffsetDateTime) -> Result<Vec<Uuid>, RepoError> {
        let filas = sqlx::query(
            "select id from tags where deleted_at is not null and updated_at > ?2 and (is_shared or created_by = ?1)",
        )
        .bind(viewer_id.to_string())
        .bind(fmt_dt(desde))
        .fetch_all(&self.pool)
        .await?;
        filas.iter().map(|f| parse_uuid(f.try_get::<String, _>("id")?.as_str())).collect()
    }
}
