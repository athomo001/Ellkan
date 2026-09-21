// Autor: Athan Espinoza

//! Segunda implementación de `RecoveryKitRepository`/`ResetTokenRepository`
//! (modo escritorio, spec/13 §4) — mismo comportamiento que
//! `repository.rs` (Postgres), dialecto SQLite. Sin `sqlx::query!`/`query_as!`:
//! activar los features `postgres` y `sqlite` de `sqlx` a la vez en el mismo
//! crate no le da a esas macros forma de saber a cuál dialecto apunta cada
//! invocación puntual (cada una resuelve contra un único `DATABASE_URL`/caché
//! offline) — se usa `sqlx::query`/`query_as` en runtime, con el costo
//! explícito de perder el chequeo de tipos en compile-time de este lado
//! (mitigado por el test de integración de este mismo módulo).

use sqlx::{Row, SqlitePool};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::desktop::sqlite_util::{fmt_dt, parse_dt, parse_uuid};
use crate::error::RepoError;

use crate::recovery_kit::models::{RecoveryKit, ResetToken};
use crate::recovery_kit::repository::{RecoveryKitRepository, ResetTokenRepository};

fn fila_a_kit(row: &sqlx::sqlite::SqliteRow) -> Result<RecoveryKit, RepoError> {
    Ok(RecoveryKit {
        id: parse_uuid(row.try_get::<String, _>("id")?.as_str())?,
        user_id: parse_uuid(row.try_get::<String, _>("user_id")?.as_str())?,
        kit_public_key_x25519: row.try_get("kit_public_key_x25519")?,
        sealed_identity_material: row.try_get("sealed_identity_material")?,
        must_rotate: row.try_get("must_rotate")?,
        created_at: parse_dt(row.try_get::<String, _>("created_at")?.as_str())?,
    })
}

fn fila_a_token(row: &sqlx::sqlite::SqliteRow) -> Result<ResetToken, RepoError> {
    let consumed_at = row.try_get::<Option<String>, _>("consumed_at")?;
    let email_code_expires_at = row.try_get::<Option<String>, _>("email_code_expires_at")?;
    Ok(ResetToken {
        id: parse_uuid(row.try_get::<String, _>("id")?.as_str())?,
        user_id: parse_uuid(row.try_get::<String, _>("user_id")?.as_str())?,
        token_hash: row.try_get("token_hash")?,
        expires_at: parse_dt(row.try_get::<String, _>("expires_at")?.as_str())?,
        consumed_at: consumed_at.map(|s| parse_dt(&s)).transpose()?,
        email_code_hash: row.try_get("email_code_hash")?,
        email_code_expires_at: email_code_expires_at.map(|s| parse_dt(&s)).transpose()?,
    })
}

#[derive(Clone)]
pub struct SqliteRecoveryKitRepository {
    pub pool: SqlitePool,
}

impl RecoveryKitRepository for SqliteRecoveryKitRepository {
    async fn upsert(
        &self,
        user_id: Uuid,
        kit_public_key_x25519: &[u8],
        sealed_identity_material: &[u8],
    ) -> Result<RecoveryKit, RepoError> {
        // El id generado acá sólo se usa si la fila es nueva — en el camino
        // de conflicto, `do update` no toca `id`, la fila existente conserva
        // el suyo (mismo comportamiento que `default uuidv7()` en Postgres,
        // que tampoco se re-evalúa en un `on conflict`).
        let id_candidato = Uuid::now_v7().to_string();
        let ahora = fmt_dt(OffsetDateTime::now_utc());

        let fila = sqlx::query(
            r#"
            insert into recovery_kits (id, user_id, kit_public_key_x25519, sealed_identity_material, updated_at)
            values (?1, ?2, ?3, ?4, ?5)
            on conflict(user_id) do update set
                kit_public_key_x25519 = excluded.kit_public_key_x25519,
                sealed_identity_material = excluded.sealed_identity_material,
                must_rotate = 0,
                updated_at = excluded.updated_at
            returning id, user_id, kit_public_key_x25519, sealed_identity_material, must_rotate, created_at
            "#,
        )
        .bind(id_candidato)
        .bind(user_id.to_string())
        .bind(kit_public_key_x25519)
        .bind(sealed_identity_material)
        .bind(ahora)
        .fetch_one(&self.pool)
        .await?;

        fila_a_kit(&fila)
    }

    async fn buscar_por_usuario(&self, user_id: Uuid) -> Result<Option<RecoveryKit>, RepoError> {
        let fila = sqlx::query(
            r#"select id, user_id, kit_public_key_x25519, sealed_identity_material, must_rotate, created_at
               from recovery_kits where user_id = ?1"#,
        )
        .bind(user_id.to_string())
        .fetch_optional(&self.pool)
        .await?;

        fila.as_ref().map(fila_a_kit).transpose()
    }

    async fn marcar_para_rotar(&self, user_id: Uuid) -> Result<(), RepoError> {
        sqlx::query(r#"update recovery_kits set must_rotate = 1 where user_id = ?1"#)
            .bind(user_id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct SqliteResetTokenRepository {
    pub pool: SqlitePool,
}

impl ResetTokenRepository for SqliteResetTokenRepository {
    async fn crear(&self, user_id: Uuid, token_hash: &[u8], expires_at: OffsetDateTime) -> Result<Uuid, RepoError> {
        let id = Uuid::now_v7();
        sqlx::query(r#"insert into recovery_reset_tokens (id, user_id, token_hash, expires_at) values (?1, ?2, ?3, ?4)"#)
            .bind(id.to_string())
            .bind(user_id.to_string())
            .bind(token_hash)
            .bind(fmt_dt(expires_at))
            .execute(&self.pool)
            .await?;
        Ok(id)
    }

    async fn buscar_vigente_por_hash(&self, token_hash: &[u8]) -> Result<Option<ResetToken>, RepoError> {
        let fila = sqlx::query(
            r#"
            select id, user_id, token_hash, expires_at, consumed_at, email_code_hash, email_code_expires_at
            from recovery_reset_tokens
            where token_hash = ?1 and consumed_at is null
              and expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            "#,
        )
        .bind(token_hash)
        .fetch_optional(&self.pool)
        .await?;

        fila.as_ref().map(fila_a_token).transpose()
    }

    async fn buscar_vigente(&self, id: Uuid) -> Result<Option<ResetToken>, RepoError> {
        let fila = sqlx::query(
            r#"
            select id, user_id, token_hash, expires_at, consumed_at, email_code_hash, email_code_expires_at
            from recovery_reset_tokens
            where id = ?1 and consumed_at is null
              and expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
            "#,
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;

        fila.as_ref().map(fila_a_token).transpose()
    }

    async fn guardar_codigo_email(
        &self,
        id: Uuid,
        code_hash: &[u8],
        expires_at: OffsetDateTime,
    ) -> Result<(), RepoError> {
        sqlx::query(
            r#"update recovery_reset_tokens set email_code_hash = ?2, email_code_expires_at = ?3 where id = ?1"#,
        )
        .bind(id.to_string())
        .bind(code_hash)
        .bind(fmt_dt(expires_at))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn marcar_consumido(&self, id: Uuid) -> Result<bool, RepoError> {
        let resultado = sqlx::query(
            r#"update recovery_reset_tokens set consumed_at = ?2 where id = ?1 and consumed_at is null"#,
        )
        .bind(id.to_string())
        .bind(fmt_dt(OffsetDateTime::now_utc()))
        .execute(&self.pool)
        .await?;
        Ok(resultado.rows_affected() == 1)
    }
}
