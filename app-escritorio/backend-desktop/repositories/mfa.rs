// Autor: Athan Espinoza

//! Segunda implementación (SQLite, modo escritorio) de los repositorios de
//! `mfa`. `MfaPolicyRepository` es la única sin tabla propia a propósito:
//! no hay política organizacional que administrar con 1 solo usuario y sin
//! admin (spec/13 §16) — `obtener()` devuelve un valor fijo en memoria
//! ("MFA no exigido"), `actualizar()` es un no-op. `TotpCredentialRepository`/
//! `MfaChallengeRepository` sí se portan completos: sin dependencia de
//! grupos/roles, y F-38 (desbloqueo rápido TOTP local) los reusa.

use sqlx::{Row, SqlitePool};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::desktop::sqlite_util::{fmt_dt, parse_dt, parse_uuid};
use crate::error::RepoError;

use crate::mfa::models::{MfaChallengeRow, MfaPolicy, TotpCredential};
use crate::mfa::repository::{MfaChallengeRepository, MfaPolicyRepository, TotpCredentialRepository};

#[derive(Clone, Default)]
pub struct SqliteMfaPolicyRepository;

impl MfaPolicyRepository for SqliteMfaPolicyRepository {
    async fn obtener(&self) -> Result<MfaPolicy, RepoError> {
        Ok(MfaPolicy {
            require_mfa: false,
            allowed_methods: vec!["totp".to_string()],
            grace_period_days: 0,
            require_mfa_since: None,
        })
    }

    async fn actualizar(&self, _policy: &MfaPolicy) -> Result<(), RepoError> {
        Ok(())
    }
}

fn fila_a_totp(row: &sqlx::sqlite::SqliteRow) -> Result<TotpCredential, RepoError> {
    let confirmed_at = row.try_get::<Option<String>, _>("confirmed_at")?;
    Ok(TotpCredential {
        id: parse_uuid(row.try_get::<String, _>("id")?.as_str())?,
        user_id: parse_uuid(row.try_get::<String, _>("user_id")?.as_str())?,
        secret_ciphertext: row.try_get("secret_ciphertext")?,
        secret_nonce: row.try_get("secret_nonce")?,
        confirmed_at: confirmed_at.map(|s| parse_dt(&s)).transpose()?,
    })
}

#[derive(Clone)]
pub struct SqliteTotpCredentialRepository {
    pub pool: SqlitePool,
}

impl TotpCredentialRepository for SqliteTotpCredentialRepository {
    async fn limpiar_pendientes(&self, user_id: Uuid) -> Result<(), RepoError> {
        sqlx::query(
            r#"update user_totp_credentials set deleted_at = ?2
               where user_id = ?1 and confirmed_at is null and deleted_at is null"#,
        )
        .bind(user_id.to_string())
        .bind(fmt_dt(OffsetDateTime::now_utc()))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn crear_pendiente(
        &self,
        user_id: Uuid,
        secret_ciphertext: &[u8],
        secret_nonce: &[u8],
    ) -> Result<TotpCredential, RepoError> {
        let id = Uuid::now_v7();
        sqlx::query(
            r#"insert into user_totp_credentials (id, user_id, secret_ciphertext, secret_nonce)
               values (?1, ?2, ?3, ?4)"#,
        )
        .bind(id.to_string())
        .bind(user_id.to_string())
        .bind(secret_ciphertext)
        .bind(secret_nonce)
        .execute(&self.pool)
        .await?;
        Ok(TotpCredential {
            id,
            user_id,
            secret_ciphertext: secret_ciphertext.to_vec(),
            secret_nonce: secret_nonce.to_vec(),
            confirmed_at: None,
        })
    }

    async fn buscar_pendiente(&self, user_id: Uuid) -> Result<Option<TotpCredential>, RepoError> {
        let fila = sqlx::query(
            r#"select id, user_id, secret_ciphertext, secret_nonce, confirmed_at
               from user_totp_credentials
               where user_id = ?1 and confirmed_at is null and deleted_at is null
               order by created_at desc limit 1"#,
        )
        .bind(user_id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        fila.as_ref().map(fila_a_totp).transpose()
    }

    async fn buscar_confirmado(&self, user_id: Uuid) -> Result<Option<TotpCredential>, RepoError> {
        let fila = sqlx::query(
            r#"select id, user_id, secret_ciphertext, secret_nonce, confirmed_at
               from user_totp_credentials
               where user_id = ?1 and confirmed_at is not null and deleted_at is null"#,
        )
        .bind(user_id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        fila.as_ref().map(fila_a_totp).transpose()
    }

    async fn confirmar(&self, id: Uuid) -> Result<(), RepoError> {
        sqlx::query(r#"update user_totp_credentials set confirmed_at = ?2 where id = ?1"#)
            .bind(id.to_string())
            .bind(fmt_dt(OffsetDateTime::now_utc()))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn revocar_confirmados_de(&self, user_id: Uuid) -> Result<(), RepoError> {
        sqlx::query(
            r#"update user_totp_credentials set deleted_at = ?2
               where user_id = ?1 and confirmed_at is not null and deleted_at is null"#,
        )
        .bind(user_id.to_string())
        .bind(fmt_dt(OffsetDateTime::now_utc()))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn marcar_paso_aceptado(&self, id: Uuid, paso: i64) -> Result<bool, RepoError> {
        let resultado = sqlx::query(
            r#"update user_totp_credentials set ultimo_paso_aceptado = ?2
               where id = ?1 and (ultimo_paso_aceptado is null or ultimo_paso_aceptado < ?2)"#,
        )
        .bind(id.to_string())
        .bind(paso)
        .execute(&self.pool)
        .await?;
        Ok(resultado.rows_affected() == 1)
    }
}

#[derive(Clone)]
pub struct SqliteMfaChallengeRepository {
    pub pool: SqlitePool,
}

impl MfaChallengeRepository for SqliteMfaChallengeRepository {
    async fn crear(
        &self,
        user_id: Uuid,
        session_hash: &[u8],
        codigo_hash: Option<&[u8]>,
        expires_at: OffsetDateTime,
    ) -> Result<(), RepoError> {
        let metodo = if codigo_hash.is_some() { "email" } else { "totp" };
        sqlx::query(
            r#"insert into mfa_challenges (id, user_id, method, session_hash, code_hash, expires_at)
               values (?1, ?2, ?3, ?4, ?5, ?6)"#,
        )
        .bind(Uuid::now_v7().to_string())
        .bind(user_id.to_string())
        .bind(metodo)
        .bind(session_hash)
        .bind(codigo_hash)
        .bind(fmt_dt(expires_at))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn listar_pendientes(&self, user_id: Uuid) -> Result<Vec<MfaChallengeRow>, RepoError> {
        let filas = sqlx::query(
            r#"select id, user_id, session_hash, code_hash from mfa_challenges
               where user_id = ?1 and consumed_at is null and expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')"#,
        )
        .bind(user_id.to_string())
        .fetch_all(&self.pool)
        .await?;

        filas
            .iter()
            .map(|f| -> Result<_, RepoError> {
                Ok(MfaChallengeRow {
                    id: parse_uuid(f.try_get::<String, _>("id")?.as_str())?,
                    user_id: parse_uuid(f.try_get::<String, _>("user_id")?.as_str())?,
                    session_hash: f.get("session_hash"),
                    code_hash: f.get("code_hash"),
                })
            })
            .collect()
    }

    async fn consumir(&self, id: Uuid) -> Result<(), RepoError> {
        sqlx::query(r#"update mfa_challenges set consumed_at = ?2 where id = ?1"#)
            .bind(id.to_string())
            .bind(fmt_dt(OffsetDateTime::now_utc()))
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
