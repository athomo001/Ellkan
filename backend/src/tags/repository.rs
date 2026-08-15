// Autor: Athan Espinoza

#![allow(async_fn_in_trait)]

use uuid::Uuid;

use crate::error::RepoError;

use super::models::Tag;

pub trait TagRepository {
    async fn crear(&self, id: Uuid, name: &str, is_shared: bool, created_by: Uuid) -> Result<Tag, RepoError>;

    async fn buscar(&self, id: Uuid) -> Result<Option<Tag>, RepoError>;

    /// Compartidos + personales del propio `viewer_id` — nunca los
    /// personales de otro usuario (F-10, criterio de aceptación literal).
    async fn listar_disponibles_para(&self, viewer_id: Uuid) -> Result<Vec<Tag>, RepoError>;

    async fn aplicar(&self, resource_id: Uuid, tag_id: Uuid) -> Result<(), RepoError>;

    async fn quitar(&self, resource_id: Uuid, tag_id: Uuid) -> Result<(), RepoError>;

    /// IDs de recurso con `tag_id` aplicado, visibles para `viewer_id` (con
    /// permiso `read`+ sobre el recurso vía `permissions`) — el filtro de
    /// visibilidad del propio tag ya no aplica acá porque para llegar a este
    /// punto el caller ya conoce `tag_id` (lo resolvió contra
    /// `listar_disponibles_para`).
    async fn recursos_visibles_con_tag(&self, viewer_id: Uuid, tag_id: Uuid) -> Result<Vec<Uuid>, RepoError>;
}

#[derive(Clone)]
pub struct PgTagRepository {
    pub pool: sqlx::PgPool,
}

impl TagRepository for PgTagRepository {
    async fn crear(&self, id: Uuid, name: &str, is_shared: bool, created_by: Uuid) -> Result<Tag, RepoError> {
        let fila = sqlx::query!(
            r#"
            insert into tags (id, name, is_shared, created_by)
            values ($1, $2, $3, $4)
            returning id, name, is_shared, created_by
            "#,
            id,
            name,
            is_shared,
            created_by,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(Tag { id: fila.id, name: fila.name, is_shared: fila.is_shared, created_by: fila.created_by })
    }

    async fn buscar(&self, id: Uuid) -> Result<Option<Tag>, RepoError> {
        let fila = sqlx::query!(
            r#"select id, name, is_shared, created_by from tags where id = $1 and deleted_at is null"#,
            id,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(fila.map(|f| Tag { id: f.id, name: f.name, is_shared: f.is_shared, created_by: f.created_by }))
    }

    async fn listar_disponibles_para(&self, viewer_id: Uuid) -> Result<Vec<Tag>, RepoError> {
        let filas = sqlx::query!(
            r#"
            select id, name, is_shared, created_by from tags
            where deleted_at is null and (is_shared or created_by = $1)
            order by name
            "#,
            viewer_id,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(filas
            .into_iter()
            .map(|f| Tag { id: f.id, name: f.name, is_shared: f.is_shared, created_by: f.created_by })
            .collect())
    }

    async fn aplicar(&self, resource_id: Uuid, tag_id: Uuid) -> Result<(), RepoError> {
        sqlx::query!(
            r#"insert into resource_tags (resource_id, tag_id) values ($1, $2) on conflict do nothing"#,
            resource_id,
            tag_id,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn quitar(&self, resource_id: Uuid, tag_id: Uuid) -> Result<(), RepoError> {
        sqlx::query!(
            r#"delete from resource_tags where resource_id = $1 and tag_id = $2"#,
            resource_id,
            tag_id,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn recursos_visibles_con_tag(&self, viewer_id: Uuid, tag_id: Uuid) -> Result<Vec<Uuid>, RepoError> {
        let filas = sqlx::query!(
            r#"
            select distinct rt.resource_id
            from resource_tags rt
            join permissions p on p.subject_type = 'resource' and p.subject_id = rt.resource_id
            where rt.tag_id = $1 and p.grantee_type = 'user' and p.grantee_id = $2
            "#,
            tag_id,
            viewer_id,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(filas.into_iter().map(|f| f.resource_id).collect())
    }
}
