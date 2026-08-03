// Autor: Athan Espinoza

#![allow(async_fn_in_trait)]

use uuid::Uuid;

use crate::error::RepoError;

use super::models::{Folder, NodoDeArbol};

pub trait FolderRepository {
    async fn crear(&self, id: Uuid, name_ciphertext: &[u8], name_nonce: &[u8]) -> Result<Folder, RepoError>;

    async fn buscar(&self, id: Uuid) -> Result<Option<Folder>, RepoError>;
}

pub trait FolderItemRepository {
    /// Posiciona (o reposiciona) `child_folder_id` bajo `parent_folder_id`
    /// (`None` = raíz) en el árbol de `user_id` — upsert sobre
    /// `unique(user_id, child_folder_id)`.
    async fn posicionar(
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
}

#[derive(Clone)]
pub struct PgFolderRepository {
    pub pool: sqlx::PgPool,
}

impl FolderRepository for PgFolderRepository {
    async fn crear(&self, id: Uuid, name_ciphertext: &[u8], name_nonce: &[u8]) -> Result<Folder, RepoError> {
        let fila = sqlx::query!(
            r#"
            insert into folders (id, name_ciphertext, name_nonce)
            values ($1, $2, $3)
            returning id, name_ciphertext, name_nonce
            "#,
            id,
            name_ciphertext,
            name_nonce,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(Folder { id: fila.id, name_ciphertext: fila.name_ciphertext, name_nonce: fila.name_nonce })
    }

    async fn buscar(&self, id: Uuid) -> Result<Option<Folder>, RepoError> {
        let fila = sqlx::query!(
            r#"select id, name_ciphertext, name_nonce from folders where id = $1 and deleted_at is null"#,
            id,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(fila.map(|f| Folder { id: f.id, name_ciphertext: f.name_ciphertext, name_nonce: f.name_nonce }))
    }
}

#[derive(Clone)]
pub struct PgFolderItemRepository {
    pub pool: sqlx::PgPool,
}

impl FolderItemRepository for PgFolderItemRepository {
    async fn posicionar(
        &self,
        user_id: Uuid,
        child_folder_id: Uuid,
        parent_folder_id: Option<Uuid>,
    ) -> Result<(), RepoError> {
        sqlx::query!(
            r#"
            insert into folder_items (folder_id, child_folder_id, user_id)
            values ($1, $2, $3)
            on conflict (user_id, child_folder_id) do update set folder_id = excluded.folder_id
            "#,
            parent_folder_id,
            child_folder_id,
            user_id,
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
                   f.name_ciphertext, f.name_nonce
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
}
