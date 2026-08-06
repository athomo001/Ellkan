// Autor: Athan Espinoza

#![allow(async_fn_in_trait)]

use serde_json::Value;

use crate::error::RepoError;

use super::models::DirectorySyncConfig;

pub trait DirectorySyncConfigRepository {
    async fn obtener(&self) -> Result<DirectorySyncConfig, RepoError>;

    #[allow(clippy::too_many_arguments)]
    async fn actualizar(
        &self,
        ldap_url: Option<&str>,
        bind_dn: Option<&str>,
        bind_password_encrypted: Option<&[u8]>,
        bind_password_nonce: Option<&[u8]>,
        require_starttls: bool,
        base_dn: Option<&str>,
        user_filter: Option<&str>,
        attribute_mapping: &Value,
    ) -> Result<(), RepoError>;

    async fn guardar_resultado_dry_run(&self, resultado: &Value) -> Result<(), RepoError>;
    async fn marcar_sync_aplicado(&self) -> Result<(), RepoError>;

    /// Uso interno del propio `DirectorySyncService` para conectarse — nunca
    /// expuesto en la respuesta de `GET /admin/directory-sync/config`.
    async fn obtener_credencial_bind(&self) -> Result<Option<(Vec<u8>, Vec<u8>)>, RepoError>;
}

#[derive(Clone)]
pub struct PgDirectorySyncConfigRepository {
    pub pool: sqlx::PgPool,
}

impl DirectorySyncConfigRepository for PgDirectorySyncConfigRepository {
    async fn obtener(&self) -> Result<DirectorySyncConfig, RepoError> {
        let fila = sqlx::query!(
            r#"
            select ldap_url, bind_dn, require_starttls, base_dn, user_filter,
                   attribute_mapping, last_sync_at
            from directory_sync_config where organization_id = 1
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        let mapping: std::collections::BTreeMap<String, String> =
            serde_json::from_value(fila.attribute_mapping).unwrap_or_default();

        Ok(DirectorySyncConfig {
            ldap_url: fila.ldap_url,
            bind_dn: fila.bind_dn,
            bind_password: None,
            require_starttls: fila.require_starttls,
            base_dn: fila.base_dn,
            user_filter: fila.user_filter,
            attribute_mapping: mapping,
            last_sync_at: fila.last_sync_at,
        })
    }

    async fn actualizar(
        &self,
        ldap_url: Option<&str>,
        bind_dn: Option<&str>,
        bind_password_encrypted: Option<&[u8]>,
        bind_password_nonce: Option<&[u8]>,
        require_starttls: bool,
        base_dn: Option<&str>,
        user_filter: Option<&str>,
        attribute_mapping: &Value,
    ) -> Result<(), RepoError> {
        sqlx::query!(
            r#"
            update directory_sync_config set
                ldap_url = $1,
                bind_dn = $2,
                bind_password_encrypted = coalesce($3, bind_password_encrypted),
                bind_password_nonce = coalesce($4, bind_password_nonce),
                require_starttls = $5,
                base_dn = $6,
                user_filter = $7,
                attribute_mapping = $8
            where organization_id = 1
            "#,
            ldap_url,
            bind_dn,
            bind_password_encrypted,
            bind_password_nonce,
            require_starttls,
            base_dn,
            user_filter,
            attribute_mapping,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn guardar_resultado_dry_run(&self, resultado: &Value) -> Result<(), RepoError> {
        sqlx::query!(
            r#"update directory_sync_config set last_sync_dry_run_result = $1 where organization_id = 1"#,
            resultado,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn marcar_sync_aplicado(&self) -> Result<(), RepoError> {
        sqlx::query!(r#"update directory_sync_config set last_sync_at = now() where organization_id = 1"#)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn obtener_credencial_bind(&self) -> Result<Option<(Vec<u8>, Vec<u8>)>, RepoError> {
        let fila = sqlx::query!(
            r#"select bind_password_encrypted, bind_password_nonce from directory_sync_config where organization_id = 1"#,
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(match (fila.bind_password_encrypted, fila.bind_password_nonce) {
            (Some(c), Some(n)) => Some((c, n)),
            _ => None,
        })
    }
}
