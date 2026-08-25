// Autor: Athan Espinoza

#![allow(async_fn_in_trait)]

use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::RepoError;

use super::models::{
    ExternalSharePolicy, FilaExternalShare, FilaExternalShareResumen, NuevoExternalShare, ResultadoAcceso,
};

pub trait ExternalShareRepository {
    async fn crear(&self, nuevo: &NuevoExternalShare) -> Result<FilaExternalShare, RepoError>;
    async fn obtener(&self, id: Uuid) -> Result<Option<FilaExternalShare>, RepoError>;
    /// F-26 UI de gestión: shares creados por `creado_por`, más nuevos primero.
    async fn listar_por_creador(&self, creado_por: Uuid) -> Result<Vec<FilaExternalShareResumen>, RepoError>;
    async fn revocar(&self, id: Uuid) -> Result<bool, RepoError>;
    /// Único punto de lectura del contenido — atómico (transacción +
    /// `FOR UPDATE`) para que dos requests concurrentes sobre un share con
    /// `max_views=1` nunca puedan leer ambas el mismo contenido: el
    /// incremento de `view_count` y el quemado (si corresponde) pasan en
    /// la misma transacción que decide el estado, serializados por el lock
    /// de fila.
    async fn acceder(&self, id: Uuid) -> Result<ResultadoAcceso, RepoError>;
    /// F-26: "borrado efectivo de ciphertext al quemar/expirar, no sólo
    /// marcarlo inactivo" — cubre el caso de un share vencido que nadie
    /// llegó a abrir nunca (`acceder` sólo quema on-access; sin este
    /// barrido, el ciphertext de un link que nadie abrió quedaría en la
    /// tabla indefinidamente). Usado por `job::spawn`.
    async fn quemar_expirados(&self) -> Result<Vec<Uuid>, RepoError>;
}

pub trait ExternalSharePolicyRepository {
    async fn obtener(&self) -> Result<ExternalSharePolicy, RepoError>;
    async fn actualizar(&self, policy: &ExternalSharePolicy) -> Result<(), RepoError>;
}

#[derive(Clone)]
pub struct PgExternalShareRepository {
    pub pool: sqlx::PgPool,
}

impl ExternalShareRepository for PgExternalShareRepository {
    async fn crear(&self, nuevo: &NuevoExternalShare) -> Result<FilaExternalShare, RepoError> {
        let fila = sqlx::query!(
            r#"
            insert into external_shares
                (created_by, ciphertext, password_protected, password_salt, max_views, expires_at)
            values ($1, $2, $3, $4, $5, $6)
            returning id, created_by, max_views, expires_at, revoked_at, burned_at
            "#,
            nuevo.created_by,
            nuevo.ciphertext,
            nuevo.password_protected,
            nuevo.password_salt,
            nuevo.max_views,
            nuevo.expires_at,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(FilaExternalShare {
            id: fila.id,
            created_by: fila.created_by,
            max_views: fila.max_views,
            expires_at: fila.expires_at,
            revoked_at: fila.revoked_at,
            burned_at: fila.burned_at,
        })
    }

    async fn obtener(&self, id: Uuid) -> Result<Option<FilaExternalShare>, RepoError> {
        let fila = sqlx::query!(
            r#"select id, created_by, max_views, expires_at, revoked_at, burned_at
               from external_shares where id = $1"#,
            id,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(fila.map(|fila| FilaExternalShare {
            id: fila.id,
            created_by: fila.created_by,
            max_views: fila.max_views,
            expires_at: fila.expires_at,
            revoked_at: fila.revoked_at,
            burned_at: fila.burned_at,
        }))
    }

    async fn listar_por_creador(&self, creado_por: Uuid) -> Result<Vec<FilaExternalShareResumen>, RepoError> {
        let filas = sqlx::query!(
            r#"select id, password_protected, max_views, view_count, expires_at,
                      revoked_at, burned_at, created_at
               from external_shares where created_by = $1 order by created_at desc"#,
            creado_por,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(filas
            .into_iter()
            .map(|f| FilaExternalShareResumen {
                id: f.id,
                password_protected: f.password_protected,
                max_views: f.max_views,
                view_count: f.view_count,
                expires_at: f.expires_at,
                revoked_at: f.revoked_at,
                burned_at: f.burned_at,
                created_at: f.created_at,
            })
            .collect())
    }

    async fn revocar(&self, id: Uuid) -> Result<bool, RepoError> {
        let resultado = sqlx::query!(
            r#"update external_shares set revoked_at = now(), ciphertext = null
               where id = $1 and revoked_at is null and burned_at is null"#,
            id,
        )
        .execute(&self.pool)
        .await?;
        Ok(resultado.rows_affected() > 0)
    }

    async fn acceder(&self, id: Uuid) -> Result<ResultadoAcceso, RepoError> {
        let mut tx = self.pool.begin().await?;

        let fila = sqlx::query!(
            r#"
            select ciphertext, password_protected, password_salt, max_views, view_count,
                   expires_at, revoked_at, burned_at
            from external_shares where id = $1 for update
            "#,
            id,
        )
        .fetch_optional(&mut *tx)
        .await?;

        let Some(fila) = fila else {
            tx.commit().await?;
            return Ok(ResultadoAcceso::NoEncontrado);
        };

        if fila.revoked_at.is_some() {
            tx.commit().await?;
            return Ok(ResultadoAcceso::Revocado);
        }
        if fila.burned_at.is_some() {
            tx.commit().await?;
            return Ok(ResultadoAcceso::Quemado);
        }
        if fila.expires_at <= OffsetDateTime::now_utc() {
            sqlx::query!(
                r#"update external_shares set burned_at = now(), ciphertext = null where id = $1"#,
                id,
            )
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Ok(ResultadoAcceso::Expirado);
        }

        let Some(ciphertext) = fila.ciphertext else {
            // Defensivo: `ciphertext` sólo debería ser null junto con
            // `burned_at`, ya descartado arriba — no debería poder llegar
            // acá, pero ante la duda se trata como ya quemado, nunca se
            // devuelve un ciphertext vacío como si fuera válido.
            tx.commit().await?;
            return Ok(ResultadoAcceso::Quemado);
        };

        let nuevas_vistas = fila.view_count + 1;
        let se_quema_ahora = nuevas_vistas >= fila.max_views;
        if se_quema_ahora {
            sqlx::query!(
                r#"update external_shares set view_count = $2, burned_at = now(), ciphertext = null where id = $1"#,
                id,
                nuevas_vistas,
            )
            .execute(&mut *tx)
            .await?;
        } else {
            sqlx::query!(
                r#"update external_shares set view_count = $2 where id = $1"#,
                id,
                nuevas_vistas,
            )
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;

        Ok(ResultadoAcceso::Ok {
            ciphertext,
            password_protected: fila.password_protected,
            password_salt: fila.password_salt,
            quemado_ahora: se_quema_ahora,
        })
    }

    async fn quemar_expirados(&self) -> Result<Vec<Uuid>, RepoError> {
        let filas = sqlx::query!(
            r#"
            update external_shares set burned_at = now(), ciphertext = null
            where revoked_at is null and burned_at is null and expires_at <= now()
            returning id
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(filas.into_iter().map(|f| f.id).collect())
    }
}

#[derive(Clone)]
pub struct PgExternalSharePolicyRepository {
    pub pool: sqlx::PgPool,
}

impl ExternalSharePolicyRepository for PgExternalSharePolicyRepository {
    async fn obtener(&self) -> Result<ExternalSharePolicy, RepoError> {
        let fila = sqlx::query!(
            r#"select enabled, max_expiration_hours, require_password, allow_link, allow_file
               from external_share_policy where organization_id = 1"#,
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(ExternalSharePolicy {
            enabled: fila.enabled,
            max_expiration_hours: fila.max_expiration_hours,
            require_password: fila.require_password,
            allow_link: fila.allow_link,
            allow_file: fila.allow_file,
        })
    }

    async fn actualizar(&self, policy: &ExternalSharePolicy) -> Result<(), RepoError> {
        sqlx::query!(
            r#"update external_share_policy
               set enabled = $1, max_expiration_hours = $2, require_password = $3,
                   allow_link = $4, allow_file = $5
               where organization_id = 1"#,
            policy.enabled,
            policy.max_expiration_hours,
            policy.require_password,
            policy.allow_link,
            policy.allow_file,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
