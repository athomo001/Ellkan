// Autor: Athan Espinoza

#![allow(async_fn_in_trait)]

use uuid::Uuid;

use crate::error::RepoError;

use super::models::Role;

pub trait RoleRepository {
    async fn listar(&self) -> Result<Vec<Role>, RepoError>;

    async fn buscar(&self, id: Uuid) -> Result<Option<Role>, RepoError>;

    async fn id_por_nombre(&self, name: &str) -> Result<Option<Uuid>, RepoError>;

    async fn crear(&self, name: &str, permisos: &[String]) -> Result<Role, RepoError>;

    async fn reemplazar_permisos(
        &self,
        role_id: Uuid,
        permisos: &[String],
    ) -> Result<Option<Role>, RepoError>;

    /// `true` si el rol del usuario tiene exactamente `permission` o el
    /// comodín `"*"` — único caso real hasta que 1.3 agregue consumidores de
    /// permisos granulares.
    async fn usuario_tiene_permiso(&self, user_id: Uuid, permission: &str) -> Result<bool, RepoError>;
}

#[derive(Clone)]
pub struct PgRoleRepository {
    pub pool: sqlx::PgPool,
}

impl PgRoleRepository {
    async fn cargar_permisos(&self, role_id: Uuid) -> Result<Vec<String>, RepoError> {
        let filas = sqlx::query!(
            r#"select permission from role_permissions where role_id = $1 order by permission"#,
            role_id,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(filas.into_iter().map(|f| f.permission).collect())
    }
}

impl RoleRepository for PgRoleRepository {
    async fn listar(&self) -> Result<Vec<Role>, RepoError> {
        let filas = sqlx::query!(r#"select id, name, created_at from roles order by created_at"#)
            .fetch_all(&self.pool)
            .await?;

        let mut roles = Vec::with_capacity(filas.len());
        for f in filas {
            let permissions = self.cargar_permisos(f.id).await?;
            roles.push(Role { id: f.id, name: f.name, permissions, created_at: f.created_at });
        }
        Ok(roles)
    }

    async fn buscar(&self, id: Uuid) -> Result<Option<Role>, RepoError> {
        let fila = sqlx::query!(r#"select id, name, created_at from roles where id = $1"#, id)
            .fetch_optional(&self.pool)
            .await?;

        match fila {
            None => Ok(None),
            Some(f) => {
                let permissions = self.cargar_permisos(f.id).await?;
                Ok(Some(Role { id: f.id, name: f.name, permissions, created_at: f.created_at }))
            }
        }
    }

    async fn id_por_nombre(&self, name: &str) -> Result<Option<Uuid>, RepoError> {
        let fila = sqlx::query!(r#"select id from roles where name = $1"#, name)
            .fetch_optional(&self.pool)
            .await?;
        Ok(fila.map(|f| f.id))
    }

    async fn crear(&self, name: &str, permisos: &[String]) -> Result<Role, RepoError> {
        let mut tx = self.pool.begin().await?;
        let fila = sqlx::query!(
            r#"insert into roles (name) values ($1) returning id, name, created_at"#,
            name,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => RepoError::Conflict,
            _ => RepoError::Database(e),
        })?;

        for permiso in permisos {
            sqlx::query!(
                r#"insert into role_permissions (role_id, permission) values ($1, $2)"#,
                fila.id,
                permiso,
            )
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;

        Ok(Role {
            id: fila.id,
            name: fila.name,
            permissions: permisos.to_vec(),
            created_at: fila.created_at,
        })
    }

    async fn reemplazar_permisos(
        &self,
        role_id: Uuid,
        permisos: &[String],
    ) -> Result<Option<Role>, RepoError> {
        let mut tx = self.pool.begin().await?;
        let fila = sqlx::query!(r#"select id, name, created_at from roles where id = $1"#, role_id)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(fila) = fila else {
            return Ok(None);
        };

        sqlx::query!(r#"delete from role_permissions where role_id = $1"#, role_id)
            .execute(&mut *tx)
            .await?;
        for permiso in permisos {
            sqlx::query!(
                r#"insert into role_permissions (role_id, permission) values ($1, $2)"#,
                role_id,
                permiso,
            )
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;

        Ok(Some(Role {
            id: fila.id,
            name: fila.name,
            permissions: permisos.to_vec(),
            created_at: fila.created_at,
        }))
    }

    async fn usuario_tiene_permiso(&self, user_id: Uuid, permission: &str) -> Result<bool, RepoError> {
        let fila = sqlx::query!(
            r#"
            select 1 as "existe!" from users u
            join role_permissions rp on rp.role_id = u.role_id
            where u.id = $1 and (rp.permission = $2 or rp.permission = '*')
            "#,
            user_id,
            permission,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(fila.is_some())
    }
}
