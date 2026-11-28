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
        user_object_class: &str,
        sync_groups: bool,
        group_membership_attribute: &str,
    ) -> Result<(), RepoError>;

    async fn guardar_resultado_dry_run(&self, resultado: &Value) -> Result<(), RepoError>;
    async fn marcar_sync_aplicado(&self) -> Result<(), RepoError>;

    /// spec/15 §3.2 (#52): política ante un directorio que no responde.
    async fn actualizar_verificacion(&self, politica: &str, grace_seconds: i32, session_revalidate_seconds: i32) -> Result<(), RepoError>;

    /// #52: las cuentas que el sync acaba de ver quedan gestionadas por el
    /// directorio (se verifican en el login) y verificadas ahora.
    async fn marcar_gestionados(&self, external_ids: &[String]) -> Result<(), RepoError>;

    /// #53: sincronización automática y tope de bajas.
    async fn actualizar_sync_automatico(&self, habilitado: bool, intervalo: i32, tope: Option<i32>) -> Result<(), RepoError>;

    /// #53: toma la corrida automática si le toca (atómico entre réplicas:
    /// corre la que logra mover `last_sync_at`). `true` = le toca a esta.
    async fn tomar_corrida_automatica(&self) -> Result<bool, RepoError>;

    async fn anotar_error_automatico(&self, error: Option<&str>) -> Result<(), RepoError>;

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
                   attribute_mapping, last_sync_at,
                   user_object_class, sync_groups, group_membership_attribute,
                   directory_unreachable_policy, grace_seconds, session_revalidate_seconds,
                   auto_sync_enabled, poll_interval_seconds, max_deactivations_per_run, last_auto_sync_error
            from directory_sync_config where organization_id = 1
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        let mapping: std::collections::BTreeMap<String, String> = serde_json::from_value(fila.attribute_mapping).unwrap_or_default();

        Ok(DirectorySyncConfig {
            ldap_url: fila.ldap_url,
            bind_dn: fila.bind_dn,
            bind_password: None,
            require_starttls: fila.require_starttls,
            base_dn: fila.base_dn,
            user_filter: fila.user_filter,
            attribute_mapping: mapping,
            last_sync_at: fila.last_sync_at,
            user_object_class: fila.user_object_class,
            sync_groups: fila.sync_groups,
            group_membership_attribute: fila.group_membership_attribute,
            directory_unreachable_policy: fila.directory_unreachable_policy,
            grace_seconds: fila.grace_seconds,
            session_revalidate_seconds: fila.session_revalidate_seconds,
            auto_sync_enabled: fila.auto_sync_enabled,
            poll_interval_seconds: fila.poll_interval_seconds,
            max_deactivations_per_run: fila.max_deactivations_per_run,
            last_auto_sync_error: fila.last_auto_sync_error,
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
        user_object_class: &str,
        sync_groups: bool,
        group_membership_attribute: &str,
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
                attribute_mapping = $8,
                user_object_class = $9,
                sync_groups = $10,
                group_membership_attribute = $11
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
            user_object_class,
            sync_groups,
            group_membership_attribute,
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

    async fn actualizar_verificacion(&self, politica: &str, grace_seconds: i32, session_revalidate_seconds: i32) -> Result<(), RepoError> {
        sqlx::query!(
            r#"update directory_sync_config
                  set directory_unreachable_policy = $1, grace_seconds = $2, session_revalidate_seconds = $3
                where organization_id = 1"#,
            politica,
            grace_seconds,
            session_revalidate_seconds,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn actualizar_sync_automatico(&self, habilitado: bool, intervalo: i32, tope: Option<i32>) -> Result<(), RepoError> {
        sqlx::query!(
            r#"update directory_sync_config
                  set auto_sync_enabled = $1, poll_interval_seconds = $2, max_deactivations_per_run = $3
                where organization_id = 1"#,
            habilitado,
            intervalo,
            tope,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn tomar_corrida_automatica(&self) -> Result<bool, RepoError> {
        let fila = sqlx::query_scalar!(
            r#"update directory_sync_config set last_sync_at = now()
                where organization_id = 1 and auto_sync_enabled and ldap_url is not null
                  and (last_sync_at is null or last_sync_at <= now() - make_interval(secs => poll_interval_seconds))
            returning organization_id"#
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(fila.is_some())
    }

    async fn anotar_error_automatico(&self, error: Option<&str>) -> Result<(), RepoError> {
        sqlx::query!(r#"update directory_sync_config set last_auto_sync_error = $1 where organization_id = 1"#, error)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn marcar_gestionados(&self, external_ids: &[String]) -> Result<(), RepoError> {
        sqlx::query!(
            r#"update users set managed_by = 'directory_sync', last_directory_check_at = now()
                where external_id = any($1) and deleted_at is null"#,
            external_ids,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn obtener_credencial_bind(&self) -> Result<Option<(Vec<u8>, Vec<u8>)>, RepoError> {
        let fila =
            sqlx::query!(r#"select bind_password_encrypted, bind_password_nonce from directory_sync_config where organization_id = 1"#,)
                .fetch_one(&self.pool)
                .await?;
        Ok(match (fila.bind_password_encrypted, fila.bind_password_nonce) {
            (Some(c), Some(n)) => Some((c, n)),
            _ => None,
        })
    }
}
