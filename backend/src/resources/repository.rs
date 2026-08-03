// Autor: Athan Espinoza

//! `async fn` en estos traits es intencional: se usan sólo dentro de este
//! crate (genéricos, no `dyn`), así que la falta de bounds explícitos de
//! `Send` en la firma del trait no es un problema real.
#![allow(async_fn_in_trait)]

use uuid::Uuid;

use crate::error::RepoError;

use super::models::{Resource, SecretEnvelope};

pub trait ResourceRepository {
    #[allow(clippy::too_many_arguments)]
    async fn crear(
        &self,
        id: Uuid,
        resource_type_id: Uuid,
        metadata_ciphertext: &[u8],
        metadata_nonce: &[u8],
        created_by: Uuid,
    ) -> Result<Resource, RepoError>;

    async fn buscar(&self, id: Uuid) -> Result<Option<Resource>, RepoError>;

    /// Recursos donde `user_id` tiene al menos permiso `read` — join contra
    /// `permissions` (sin grupos todavía, F-11 básico).
    async fn listar_visibles_por(&self, user_id: Uuid) -> Result<Vec<Resource>, RepoError>;
}

pub trait ResourceTypeRepository {
    async fn id_por_slug(&self, slug: &str) -> Result<Option<Uuid>, RepoError>;
}

pub trait SecretEnvelopeRepository {
    #[allow(clippy::too_many_arguments)]
    async fn insertar(
        &self,
        resource_id: Uuid,
        user_id: Uuid,
        sealed_dek: &[u8],
        secret_ciphertext: &[u8],
        secret_nonce: &[u8],
    ) -> Result<(), RepoError>;

    async fn buscar(
        &self,
        resource_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<SecretEnvelope>, RepoError>;
}

pub trait PermissionRepository {
    async fn otorgar(
        &self,
        resource_id: Uuid,
        user_id: Uuid,
        nivel: &str,
    ) -> Result<(), RepoError>;

    /// `true` si `user_id` tiene exactamente `nivel` o uno más alto
    /// (`owner` > `update` > `read`) sobre el recurso.
    async fn tiene_permiso(
        &self,
        resource_id: Uuid,
        user_id: Uuid,
        nivel_minimo: &str,
    ) -> Result<bool, RepoError>;
}

#[derive(Clone)]
pub struct PgResourceRepository {
    pub pool: sqlx::PgPool,
}

impl ResourceRepository for PgResourceRepository {
    async fn crear(
        &self,
        id: Uuid,
        resource_type_id: Uuid,
        metadata_ciphertext: &[u8],
        metadata_nonce: &[u8],
        created_by: Uuid,
    ) -> Result<Resource, RepoError> {
        let fila = sqlx::query!(
            r#"
            insert into resources (id, resource_type_id, metadata_ciphertext, metadata_nonce, created_by)
            values ($1, $2, $3, $4, $5)
            returning id, resource_type_id, metadata_ciphertext, metadata_nonce, created_by, created_at
            "#,
            id,
            resource_type_id,
            metadata_ciphertext,
            metadata_nonce,
            created_by,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(Resource {
            id: fila.id,
            resource_type_id: fila.resource_type_id,
            metadata_ciphertext: fila.metadata_ciphertext,
            metadata_nonce: fila.metadata_nonce,
            created_by: fila.created_by,
            created_at: fila.created_at,
        })
    }

    async fn buscar(&self, id: Uuid) -> Result<Option<Resource>, RepoError> {
        let fila = sqlx::query!(
            r#"
            select id, resource_type_id, metadata_ciphertext, metadata_nonce, created_by, created_at
            from resources where id = $1 and deleted_at is null
            "#,
            id,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(fila.map(|f| Resource {
            id: f.id,
            resource_type_id: f.resource_type_id,
            metadata_ciphertext: f.metadata_ciphertext,
            metadata_nonce: f.metadata_nonce,
            created_by: f.created_by,
            created_at: f.created_at,
        }))
    }

    async fn listar_visibles_por(&self, user_id: Uuid) -> Result<Vec<Resource>, RepoError> {
        let filas = sqlx::query!(
            r#"
            select distinct r.id, r.resource_type_id, r.metadata_ciphertext, r.metadata_nonce,
                   r.created_by, r.created_at
            from resources r
            join permissions p on p.subject_type = 'resource' and p.subject_id = r.id
            where p.grantee_type = 'user' and p.grantee_id = $1 and r.deleted_at is null
            order by r.created_at desc
            "#,
            user_id,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(filas
            .into_iter()
            .map(|f| Resource {
                id: f.id,
                resource_type_id: f.resource_type_id,
                metadata_ciphertext: f.metadata_ciphertext,
                metadata_nonce: f.metadata_nonce,
                created_by: f.created_by,
                created_at: f.created_at,
            })
            .collect())
    }
}

#[derive(Clone)]
pub struct PgResourceTypeRepository {
    pub pool: sqlx::PgPool,
}

impl ResourceTypeRepository for PgResourceTypeRepository {
    async fn id_por_slug(&self, slug: &str) -> Result<Option<Uuid>, RepoError> {
        let fila = sqlx::query!(
            r#"select id from resource_types where slug = $1 and deleted_at is null"#,
            slug,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(fila.map(|f| f.id))
    }
}

#[derive(Clone)]
pub struct PgSecretEnvelopeRepository {
    pub pool: sqlx::PgPool,
}

impl SecretEnvelopeRepository for PgSecretEnvelopeRepository {
    async fn insertar(
        &self,
        resource_id: Uuid,
        user_id: Uuid,
        sealed_dek: &[u8],
        secret_ciphertext: &[u8],
        secret_nonce: &[u8],
    ) -> Result<(), RepoError> {
        sqlx::query!(
            r#"
            insert into secret_envelopes (resource_id, user_id, sealed_dek, secret_ciphertext, secret_nonce)
            values ($1, $2, $3, $4, $5)
            "#,
            resource_id,
            user_id,
            sealed_dek,
            secret_ciphertext,
            secret_nonce,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => RepoError::Conflict,
            _ => RepoError::Database(e),
        })?;
        Ok(())
    }

    async fn buscar(
        &self,
        resource_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<SecretEnvelope>, RepoError> {
        let fila = sqlx::query!(
            r#"
            select sealed_dek, secret_ciphertext, secret_nonce
            from secret_envelopes where resource_id = $1 and user_id = $2
            "#,
            resource_id,
            user_id,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(fila.map(|f| SecretEnvelope {
            sealed_dek: f.sealed_dek,
            secret_ciphertext: f.secret_ciphertext,
            secret_nonce: f.secret_nonce,
        }))
    }
}

#[derive(Clone)]
pub struct PgPermissionRepository {
    pub pool: sqlx::PgPool,
}

impl PermissionRepository for PgPermissionRepository {
    async fn otorgar(&self, resource_id: Uuid, user_id: Uuid, nivel: &str) -> Result<(), RepoError> {
        sqlx::query!(
            r#"
            insert into permissions (subject_type, subject_id, grantee_type, grantee_id, level)
            values ('resource', $1, 'user', $2, $3)
            on conflict (subject_type, subject_id, grantee_type, grantee_id)
            do update set level = excluded.level
            "#,
            resource_id,
            user_id,
            nivel,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn tiene_permiso(
        &self,
        resource_id: Uuid,
        user_id: Uuid,
        nivel_minimo: &str,
    ) -> Result<bool, RepoError> {
        let fila = sqlx::query!(
            r#"
            select level from permissions
            where subject_type = 'resource' and subject_id = $1
              and grantee_type = 'user' and grantee_id = $2
            "#,
            resource_id,
            user_id,
        )
        .fetch_optional(&self.pool)
        .await?;

        let orden = |n: &str| match n {
            "read" => 0,
            "update" => 1,
            "owner" => 2,
            _ => -1,
        };

        Ok(fila.is_some_and(|f| orden(&f.level) >= orden(nivel_minimo)))
    }
}
