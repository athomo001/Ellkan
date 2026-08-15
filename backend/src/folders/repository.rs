// Autor: Athan Espinoza

#![allow(async_fn_in_trait)]

use std::collections::HashMap;

use uuid::Uuid;

use crate::error::RepoError;

use super::models::{Folder, NodoDeArbol};

pub trait FolderRepository {
    async fn crear(&self, id: Uuid) -> Result<Folder, RepoError>;

    async fn buscar(&self, id: Uuid) -> Result<Option<Folder>, RepoError>;

    /// `folder_id` y todos sus ancestros hasta la raíz, inclusive, EN EL
    /// ÁRBOL DE `user_id` — a diferencia de `groups` (árbol único global),
    /// `folder_items` es por-usuario (F-09: cada usuario puede tener la
    /// misma carpeta en una posición distinta), así que "ancestro" sólo
    /// tiene sentido relativo a la vista de un usuario puntual. Mismo
    /// patrón que `GroupRepository::ancestros_inclusive` (CTE recursivo),
    /// adaptado para caminar `folder_items.folder_id` en vez de
    /// `groups.parent_group_id`.
    async fn ancestros_inclusive(&self, user_id: Uuid, folder_id: Uuid) -> Result<Vec<Uuid>, RepoError>;

    /// Profundidad de `folder_id` en el árbol de `user_id` — raíz = 1.
    async fn profundidad(&self, user_id: Uuid, folder_id: Uuid) -> Result<i32, RepoError>;

    /// Todos los descendientes de `folder_id` (sin incluirlo) en el árbol de
    /// `user_id` — usado por `?incluir_subcarpetas=true`.
    async fn descendientes_de(&self, user_id: Uuid, folder_id: Uuid) -> Result<Vec<Uuid>, RepoError>;
}

pub trait FolderItemRepository {
    /// Alta de una carpeta en el árbol de `user_id` — usado al crearla
    /// (nombre propio) y al compartirla con alguien más (nombre resellado
    /// para esa persona, client-side). Upsert sobre `unique(user_id,
    /// child_folder_id)`, por si ya estaba (re-compartir/re-sellar).
    async fn insertar_carpeta(
        &self,
        user_id: Uuid,
        child_folder_id: Uuid,
        parent_folder_id: Option<Uuid>,
        name_ciphertext: &[u8],
        name_nonce: &[u8],
    ) -> Result<(), RepoError>;

    /// Reposiciona (sólo el padre) una carpeta ya existente en el árbol de
    /// `user_id` — nunca toca el nombre ni la vista de otro usuario.
    async fn reposicionar_carpeta(
        &self,
        user_id: Uuid,
        child_folder_id: Uuid,
        parent_folder_id: Option<Uuid>,
    ) -> Result<(), RepoError>;

    /// `true` si `user_id` ya tiene a `child_folder_id` en su árbol (en
    /// cualquier posición) — una carpeta que un usuario nunca vio no es
    /// suya para mover.
    async fn tiene_en_su_arbol(&self, user_id: Uuid, child_folder_id: Uuid) -> Result<bool, RepoError>;

    async fn arbol_de(&self, user_id: Uuid) -> Result<Vec<NodoDeArbol>, RepoError>;

    /// F-11: posiciona (o reposiciona) un RECURSO dentro de una carpeta (o
    /// `None` = raíz) para `user_id` — a diferencia de una carpeta, un
    /// recurso no lleva nombre propio acá (su metadata ya vive cifrada en
    /// `resources`), sólo la posición. Upsert sobre `unique(user_id,
    /// resource_id)`.
    async fn posicionar_recurso(
        &self,
        user_id: Uuid,
        resource_id: Uuid,
        parent_folder_id: Option<Uuid>,
    ) -> Result<(), RepoError>;

    /// Mapa recurso→carpeta del árbol de `user_id` — usado para filtrar
    /// `GET /resources?folder_id=`. Un recurso ausente del mapa está en la
    /// raíz (nunca posicionado, o repuesto a `None` explícitamente).
    async fn posiciones_de_recursos(&self, user_id: Uuid) -> Result<HashMap<Uuid, Uuid>, RepoError>;

    /// 2026-08-11: todas las carpetas (de cualquier usuario) donde
    /// `resource_id` está posicionado — usado por `DELETE /resources/{id}`
    /// para saber si el recurso vive en alguna carpeta de grupo (borrado
    /// restringido a admin de ese grupo) o no (borrado con el criterio de
    /// `owner` de siempre).
    async fn carpetas_de_recurso(&self, resource_id: Uuid) -> Result<Vec<Uuid>, RepoError>;
}

#[derive(Clone)]
pub struct PgFolderRepository {
    pub pool: sqlx::PgPool,
}

impl FolderRepository for PgFolderRepository {
    async fn crear(&self, id: Uuid) -> Result<Folder, RepoError> {
        let fila = sqlx::query!(r#"insert into folders (id) values ($1) returning id"#, id)
            .fetch_one(&self.pool)
            .await?;
        Ok(Folder { id: fila.id })
    }

    async fn buscar(&self, id: Uuid) -> Result<Option<Folder>, RepoError> {
        let fila = sqlx::query!(r#"select id from folders where id = $1 and deleted_at is null"#, id,)
            .fetch_optional(&self.pool)
            .await?;

        Ok(fila.map(|f| Folder { id: f.id }))
    }

    async fn ancestros_inclusive(&self, user_id: Uuid, folder_id: Uuid) -> Result<Vec<Uuid>, RepoError> {
        let filas = sqlx::query!(
            r#"
            with recursive ancestros as (
                select child_folder_id as id, folder_id as parent
                from folder_items
                where user_id = $1 and child_folder_id = $2
                union all
                select fi.child_folder_id, fi.folder_id
                from folder_items fi
                join ancestros a on fi.child_folder_id = a.parent and fi.user_id = $1
            )
            select id as "id!" from ancestros
            "#,
            user_id,
            folder_id,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(filas.into_iter().map(|f| f.id).collect())
    }

    async fn profundidad(&self, user_id: Uuid, folder_id: Uuid) -> Result<i32, RepoError> {
        Ok(self.ancestros_inclusive(user_id, folder_id).await?.len() as i32)
    }

    async fn descendientes_de(&self, user_id: Uuid, folder_id: Uuid) -> Result<Vec<Uuid>, RepoError> {
        let filas = sqlx::query!(
            r#"
            with recursive descendientes as (
                select child_folder_id as id from folder_items
                where user_id = $1 and folder_id = $2 and child_folder_id is not null
                union all
                select fi.child_folder_id
                from folder_items fi
                join descendientes d on fi.folder_id = d.id
                where fi.user_id = $1 and fi.child_folder_id is not null
            )
            select id as "id!" from descendientes
            "#,
            user_id,
            folder_id,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(filas.into_iter().map(|f| f.id).collect())
    }
}

#[derive(Clone)]
pub struct PgFolderItemRepository {
    pub pool: sqlx::PgPool,
}

impl FolderItemRepository for PgFolderItemRepository {
    async fn insertar_carpeta(
        &self,
        user_id: Uuid,
        child_folder_id: Uuid,
        parent_folder_id: Option<Uuid>,
        name_ciphertext: &[u8],
        name_nonce: &[u8],
    ) -> Result<(), RepoError> {
        sqlx::query!(
            r#"
            insert into folder_items (folder_id, child_folder_id, user_id, name_ciphertext, name_nonce)
            values ($1, $2, $3, $4, $5)
            on conflict (user_id, child_folder_id) do update set
                folder_id = excluded.folder_id,
                name_ciphertext = excluded.name_ciphertext,
                name_nonce = excluded.name_nonce
            "#,
            parent_folder_id,
            child_folder_id,
            user_id,
            name_ciphertext,
            name_nonce,
        )
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
        sqlx::query!(
            r#"update folder_items set folder_id = $1 where user_id = $2 and child_folder_id = $3"#,
            parent_folder_id,
            user_id,
            child_folder_id,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn tiene_en_su_arbol(&self, user_id: Uuid, child_folder_id: Uuid) -> Result<bool, RepoError> {
        let fila = sqlx::query!(
            r#"select 1 as "existe!" from folder_items where user_id = $1 and child_folder_id = $2"#,
            user_id,
            child_folder_id,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(fila.is_some())
    }

    async fn arbol_de(&self, user_id: Uuid) -> Result<Vec<NodoDeArbol>, RepoError> {
        let filas = sqlx::query!(
            r#"
            select fi.child_folder_id as "folder_id!", fi.folder_id as parent_folder_id,
                   fi.name_ciphertext as "name_ciphertext!", fi.name_nonce as "name_nonce!"
            from folder_items fi
            join folders f on f.id = fi.child_folder_id
            where fi.user_id = $1 and f.deleted_at is null
            order by f.id
            "#,
            user_id,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(filas
            .into_iter()
            .map(|f| NodoDeArbol {
                folder_id: f.folder_id,
                parent_folder_id: f.parent_folder_id,
                name_ciphertext: f.name_ciphertext,
                name_nonce: f.name_nonce,
            })
            .collect())
    }

    async fn posicionar_recurso(
        &self,
        user_id: Uuid,
        resource_id: Uuid,
        parent_folder_id: Option<Uuid>,
    ) -> Result<(), RepoError> {
        sqlx::query!(
            r#"
            insert into folder_items (folder_id, resource_id, user_id)
            values ($1, $2, $3)
            on conflict (user_id, resource_id) do update set folder_id = excluded.folder_id
            "#,
            parent_folder_id,
            resource_id,
            user_id,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn posiciones_de_recursos(&self, user_id: Uuid) -> Result<HashMap<Uuid, Uuid>, RepoError> {
        let filas = sqlx::query!(
            r#"
            select resource_id as "resource_id!", folder_id as "folder_id!"
            from folder_items
            where user_id = $1 and resource_id is not null and folder_id is not null
            "#,
            user_id,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(filas.into_iter().map(|f| (f.resource_id, f.folder_id)).collect())
    }

    async fn carpetas_de_recurso(&self, resource_id: Uuid) -> Result<Vec<Uuid>, RepoError> {
        let filas = sqlx::query!(
            r#"select distinct folder_id as "folder_id!" from folder_items
               where resource_id = $1 and folder_id is not null"#,
            resource_id,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(filas.into_iter().map(|f| f.folder_id).collect())
    }
}
