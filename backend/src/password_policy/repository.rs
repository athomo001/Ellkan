// Autor: Athan Espinoza

#![allow(async_fn_in_trait)]

use crate::error::RepoError;

use super::models::PasswordPolicy;

pub trait PasswordPolicyRepository {
    async fn obtener(&self) -> Result<PasswordPolicy, RepoError>;
    async fn actualizar(&self, policy: &PasswordPolicy) -> Result<(), RepoError>;
}

#[derive(Clone)]
pub struct PgPasswordPolicyRepository {
    pub pool: sqlx::PgPool,
}

impl PasswordPolicyRepository for PgPasswordPolicyRepository {
    async fn obtener(&self) -> Result<PasswordPolicy, RepoError> {
        let fila = sqlx::query!(
            r#"
            select min_passphrase_length, min_passphrase_entropy_bits, passphrase_rotation_days,
                   generator_default_length, generator_charset_rules,
                   max_clipboard_clear_minutes, max_auto_lock_minutes
            from password_policy where organization_id = 1
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(PasswordPolicy {
            min_passphrase_length: fila.min_passphrase_length,
            min_passphrase_entropy_bits: fila.min_passphrase_entropy_bits,
            passphrase_rotation_days: fila.passphrase_rotation_days,
            generator_default_length: fila.generator_default_length,
            generator_charset_rules: fila.generator_charset_rules,
            max_clipboard_clear_minutes: fila.max_clipboard_clear_minutes,
            max_auto_lock_minutes: fila.max_auto_lock_minutes,
        })
    }

    async fn actualizar(&self, policy: &PasswordPolicy) -> Result<(), RepoError> {
        sqlx::query!(
            r#"
            update password_policy set
                min_passphrase_length = $1,
                min_passphrase_entropy_bits = $2,
                passphrase_rotation_days = $3,
                generator_default_length = $4,
                generator_charset_rules = $5,
                max_clipboard_clear_minutes = $6,
                max_auto_lock_minutes = $7
            where organization_id = 1
            "#,
            policy.min_passphrase_length,
            policy.min_passphrase_entropy_bits,
            policy.passphrase_rotation_days,
            policy.generator_default_length,
            policy.generator_charset_rules,
            policy.max_clipboard_clear_minutes,
            policy.max_auto_lock_minutes,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
