// Autor: Athan Espinoza

#![allow(async_fn_in_trait)]

use crate::error::RepoError;

/// Sólo lo que ningún otro repository ya expone — SMTP/SSO/directory
/// sync/rotación de clave de metadata se leen directo de sus propios
/// repositories existentes desde el `Service` (ver `service.rs`).
pub trait SystemStatusRepository {
    async fn ping(&self) -> Result<(), RepoError>;

    /// `(total, fallidas)` — `_sqlx_migrations` es la tabla de bookkeeping
    /// que `sqlx::migrate!` mantiene sola al arrancar, no hay que inventar
    /// tracking nuevo (columna `success` ya existe).
    async fn migraciones(&self) -> Result<(i64, i64), RepoError>;

    /// Usuarios activos con el comodín `"*"` — hallazgo real de uso: la
    /// página nunca decía si había algún admin, que es la pregunta más
    /// básica de "¿está todo bien configurado?" de todas.
    async fn contar_admins(&self) -> Result<i64, RepoError>;
}

#[derive(Clone)]
pub struct PgSystemStatusRepository {
    pub pool: sqlx::PgPool,
}

impl SystemStatusRepository for PgSystemStatusRepository {
    async fn ping(&self) -> Result<(), RepoError> {
        sqlx::query("select 1").execute(&self.pool).await?;
        Ok(())
    }

    async fn migraciones(&self) -> Result<(i64, i64), RepoError> {
        let fila = sqlx::query!(
            r#"select count(*) as "total!", count(*) filter (where not success) as "fallidas!"
               from _sqlx_migrations"#,
        )
        .fetch_one(&self.pool)
        .await?;
        Ok((fila.total, fila.fallidas))
    }

    async fn contar_admins(&self) -> Result<i64, RepoError> {
        let fila = sqlx::query!(
            r#"
            select count(*) as "total!" from users u
            join role_permissions rp on rp.role_id = u.role_id
            where rp.permission = '*' and u.active and u.deleted_at is null
            "#,
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(fila.total)
    }
}
