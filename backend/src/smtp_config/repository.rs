// Autor: Athan Espinoza

use std::future::Future;

use crate::error::RepoError;

use super::models::SmtpConfig;

/// `-> impl Future<...> + Send` en vez de `async fn` (a diferencia de otros
/// repositorios del proyecto) — este trait se usa dentro de
/// `notificaciones::spawn_poller_de_envio` (`tokio::spawn`), que exige que
/// el future completo sea `Send`; `async fn` en un trait no lo garantiza.
pub trait SmtpConfigRepository {
    fn obtener(&self) -> impl Future<Output = Result<SmtpConfig, RepoError>> + Send;
    fn actualizar(&self, config: &SmtpConfig) -> impl Future<Output = Result<(), RepoError>> + Send;
}

#[derive(Clone)]
pub struct PgSmtpConfigRepository {
    pub pool: sqlx::PgPool,
}

impl SmtpConfigRepository for PgSmtpConfigRepository {
    async fn obtener(&self) -> Result<SmtpConfig, RepoError> {
        let fila = sqlx::query!(
            r#"select host, port, from_address, tls, username, password_ciphertext, password_nonce
               from smtp_config where organization_id = 1"#,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(SmtpConfig {
            host: fila.host,
            port: fila.port,
            from_address: fila.from_address,
            tls: fila.tls,
            username: fila.username,
            password_ciphertext: fila.password_ciphertext,
            password_nonce: fila.password_nonce,
        })
    }

    async fn actualizar(&self, config: &SmtpConfig) -> Result<(), RepoError> {
        sqlx::query!(
            r#"update smtp_config set host = $1, port = $2, from_address = $3, tls = $4,
               username = $5, password_ciphertext = $6, password_nonce = $7, updated_at = now()
               where organization_id = 1"#,
            config.host,
            config.port,
            config.from_address,
            config.tls,
            config.username,
            config.password_ciphertext,
            config.password_nonce,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
