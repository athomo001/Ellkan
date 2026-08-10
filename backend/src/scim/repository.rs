// Autor: Athan Espinoza

#![allow(async_fn_in_trait)]

use uuid::Uuid;

use crate::error::RepoError;

use super::models::ScimUser;

pub trait ScimTokenRepository {
    async fn crear(&self, id: Uuid, token_hash: &[u8]) -> Result<(), RepoError>;
    async fn valido(&self, token_hash: &[u8]) -> Result<bool, RepoError>;
}

pub trait ScimUserRepository {
    async fn buscar_por_external_id(&self, external_id: &str) -> Result<Option<ScimUser>, RepoError>;
    async fn buscar_por_email(&self, email: &str) -> Result<Option<ScimUser>, RepoError>;
    async fn buscar_por_id(&self, id: Uuid) -> Result<Option<ScimUser>, RepoError>;

    /// Alta con material criptográfico placeholder (igual criterio que el
    /// JIT provisioning de F-17): el usuario existe como fila, pero no
    /// puede operar realmente hasta completar su propio enrolamiento
    /// (Argon2id/keypair, F-01) — SCIM aprovisiona la cuenta, nunca inventa
    /// claves en su nombre.
    async fn crear(&self, external_id: &str, email: &str, display_name: &str) -> Result<ScimUser, RepoError>;

    async fn listar(&self, start_index: i64, count: i64) -> Result<(Vec<ScimUser>, i64), RepoError>;

    async fn actualizar_activo(&self, id: Uuid, active: bool) -> Result<bool, RepoError>;
}

#[derive(Clone)]
pub struct PgScimTokenRepository {
    pub pool: sqlx::PgPool,
}

impl ScimTokenRepository for PgScimTokenRepository {
    async fn crear(&self, id: Uuid, token_hash: &[u8]) -> Result<(), RepoError> {
        sqlx::query!(
            r#"insert into scim_tokens (id, organization_id, token_hash) values ($1, 1, $2)"#,
            id,
            token_hash,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn valido(&self, token_hash: &[u8]) -> Result<bool, RepoError> {
        let fila = sqlx::query!(
            r#"select 1 as "existe!" from scim_tokens where token_hash = $1 and revoked_at is null"#,
            token_hash,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(fila.is_some())
    }
}

#[derive(Clone)]
pub struct PgScimUserRepository {
    pub pool: sqlx::PgPool,
}

fn fila_a_scim_user(id: Uuid, external_id: Option<String>, email: String, display_name: String, active: bool) -> ScimUser {
    ScimUser { id, external_id, email, display_name, active }
}

impl ScimUserRepository for PgScimUserRepository {
    async fn buscar_por_external_id(&self, external_id: &str) -> Result<Option<ScimUser>, RepoError> {
        let fila = sqlx::query!(
            r#"select id, external_id, email, display_name, active from users
               where external_id = $1 and deleted_at is null"#,
            external_id,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(fila.map(|f| fila_a_scim_user(f.id, f.external_id, f.email, f.display_name, f.active)))
    }

    async fn buscar_por_email(&self, email: &str) -> Result<Option<ScimUser>, RepoError> {
        let fila = sqlx::query!(
            r#"select id, external_id, email, display_name, active from users
               where email = $1 and deleted_at is null"#,
            email,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(fila.map(|f| fila_a_scim_user(f.id, f.external_id, f.email, f.display_name, f.active)))
    }

    async fn buscar_por_id(&self, id: Uuid) -> Result<Option<ScimUser>, RepoError> {
        let fila = sqlx::query!(
            r#"select id, external_id, email, display_name, active from users
               where id = $1 and deleted_at is null"#,
            id,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(fila.map(|f| fila_a_scim_user(f.id, f.external_id, f.email, f.display_name, f.active)))
    }

    async fn crear(&self, external_id: &str, email: &str, display_name: &str) -> Result<ScimUser, RepoError> {
        let mut tx = self.pool.begin().await?;
        // F-24: provisioning vía SCIM/directory sync es una fuente confiable
        // aparte (el directorio ya validó el email) — nunca pasa por la
        // verificación de email de auto-registro público.
        let fila = sqlx::query!(
            r#"
            insert into users (email, display_name, external_id, role_id, email_verified_at)
            values ($1, $2, $3, (select id from roles where name = 'user'), now())
            returning id, external_id, email, display_name, active
            "#,
            email,
            display_name,
            external_id,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => RepoError::Conflict,
            _ => RepoError::Database(e),
        })?;

        sqlx::query!(
            r#"
            insert into user_keys (
                user_id, public_key_x25519, public_key_ed25519,
                encrypted_private_key_blob, private_key_nonce, kdf_salt
            )
            values ($1, $2, $2, $3, $4, $4)
            "#,
            fila.id,
            [0u8; 32].as_slice(),
            Vec::<u8>::new(),
            [0u8; 16].as_slice(),
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(fila_a_scim_user(fila.id, fila.external_id, fila.email, fila.display_name, fila.active))
    }

    async fn listar(&self, start_index: i64, count: i64) -> Result<(Vec<ScimUser>, i64), RepoError> {
        let total = sqlx::query!(
            r#"select count(*) as "total!" from users where external_id is not null and deleted_at is null"#,
        )
        .fetch_one(&self.pool)
        .await?
        .total;

        let filas = sqlx::query!(
            r#"
            select id, external_id, email, display_name, active from users
            where external_id is not null and deleted_at is null
            order by created_at
            offset $1 limit $2
            "#,
            start_index,
            count,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok((
            filas.into_iter().map(|f| fila_a_scim_user(f.id, f.external_id, f.email, f.display_name, f.active)).collect(),
            total,
        ))
    }

    async fn actualizar_activo(&self, id: Uuid, active: bool) -> Result<bool, RepoError> {
        // Rotar `security_stamp` siempre (no sólo al desactivar) es
        // inofensivo — invalida sesiones viejas igual, nunca las nuevas —
        // y evita tener dos ramas de SQL para el mismo UPDATE.
        let resultado = sqlx::query!(
            r#"update users set active = $2, security_stamp = gen_random_uuid()
               where id = $1 and external_id is not null and deleted_at is null"#,
            id,
            active,
        )
        .execute(&self.pool)
        .await?;
        Ok(resultado.rows_affected() == 1)
    }
}
