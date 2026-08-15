// Autor: Athan Espinoza

#![allow(async_fn_in_trait)]

use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::RepoError;

use super::models::{RecoveryKit, ResetToken};

pub trait RecoveryKitRepository {
    /// Re-generar reemplaza el kit anterior (`on conflict (user_id)`) y
    /// limpia `must_rotate` — un kit recién generado nunca nace marcado
    /// para rotar, y el servidor nunca conserva el valor anterior.
    async fn upsert(
        &self,
        user_id: Uuid,
        kit_public_key_x25519: &[u8],
        sealed_identity_material: &[u8],
    ) -> Result<RecoveryKit, RepoError>;

    async fn buscar_por_usuario(&self, user_id: Uuid) -> Result<Option<RecoveryKit>, RepoError>;

    /// El kit que se acaba de usar para un reset queda obsoleto — se fuerza
    /// reemplazo en el próximo login (`recovery_kit::service::completar_reset`).
    async fn marcar_para_rotar(&self, user_id: Uuid) -> Result<(), RepoError>;
}

pub trait ResetTokenRepository {
    async fn crear(&self, user_id: Uuid, token_hash: &[u8], expires_at: OffsetDateTime) -> Result<Uuid, RepoError>;

    /// Sólo tokens vigentes (no consumidos, no vencidos) — mismo filtro que
    /// `MfaChallengeRepository::listar_pendientes`.
    async fn buscar_vigente_por_hash(&self, token_hash: &[u8]) -> Result<Option<ResetToken>, RepoError>;

    async fn buscar_vigente(&self, id: Uuid) -> Result<Option<ResetToken>, RepoError>;

    async fn guardar_codigo_email(
        &self,
        id: Uuid,
        code_hash: &[u8],
        expires_at: OffsetDateTime,
    ) -> Result<(), RepoError>;

    /// Update condicional (`where consumed_at is null`) — mismo idiom de
    /// lock optimista que `RecoveryRequestRepository::marcar_completada`.
    async fn marcar_consumido(&self, id: Uuid) -> Result<bool, RepoError>;
}

fn fila_a_kit(
    id: Uuid,
    user_id: Uuid,
    kit_public_key_x25519: Vec<u8>,
    sealed_identity_material: Vec<u8>,
    must_rotate: bool,
    created_at: OffsetDateTime,
) -> RecoveryKit {
    RecoveryKit { id, user_id, kit_public_key_x25519, sealed_identity_material, must_rotate, created_at }
}

#[allow(clippy::too_many_arguments)]
fn fila_a_token(
    id: Uuid,
    user_id: Uuid,
    token_hash: Vec<u8>,
    expires_at: OffsetDateTime,
    consumed_at: Option<OffsetDateTime>,
    email_code_hash: Option<Vec<u8>>,
    email_code_expires_at: Option<OffsetDateTime>,
) -> ResetToken {
    ResetToken { id, user_id, token_hash, expires_at, consumed_at, email_code_hash, email_code_expires_at }
}

#[derive(Clone)]
pub struct PgRecoveryKitRepository {
    pub pool: sqlx::PgPool,
}

impl RecoveryKitRepository for PgRecoveryKitRepository {
    async fn upsert(
        &self,
        user_id: Uuid,
        kit_public_key_x25519: &[u8],
        sealed_identity_material: &[u8],
    ) -> Result<RecoveryKit, RepoError> {
        let fila = sqlx::query!(
            r#"
            insert into recovery_kits (user_id, kit_public_key_x25519, sealed_identity_material)
            values ($1, $2, $3)
            on conflict (user_id) do update set
                kit_public_key_x25519 = excluded.kit_public_key_x25519,
                sealed_identity_material = excluded.sealed_identity_material,
                must_rotate = false,
                updated_at = now()
            returning id, user_id, kit_public_key_x25519, sealed_identity_material, must_rotate, created_at
            "#,
            user_id,
            kit_public_key_x25519,
            sealed_identity_material,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(fila_a_kit(fila.id, fila.user_id, fila.kit_public_key_x25519, fila.sealed_identity_material, fila.must_rotate, fila.created_at))
    }

    async fn buscar_por_usuario(&self, user_id: Uuid) -> Result<Option<RecoveryKit>, RepoError> {
        let fila = sqlx::query!(
            r#"select id, user_id, kit_public_key_x25519, sealed_identity_material, must_rotate, created_at
               from recovery_kits where user_id = $1"#,
            user_id,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(fila.map(|f| {
            fila_a_kit(f.id, f.user_id, f.kit_public_key_x25519, f.sealed_identity_material, f.must_rotate, f.created_at)
        }))
    }

    async fn marcar_para_rotar(&self, user_id: Uuid) -> Result<(), RepoError> {
        sqlx::query!(r#"update recovery_kits set must_rotate = true where user_id = $1"#, user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct PgResetTokenRepository {
    pub pool: sqlx::PgPool,
}

impl ResetTokenRepository for PgResetTokenRepository {
    async fn crear(&self, user_id: Uuid, token_hash: &[u8], expires_at: OffsetDateTime) -> Result<Uuid, RepoError> {
        let fila = sqlx::query!(
            r#"insert into recovery_reset_tokens (user_id, token_hash, expires_at) values ($1, $2, $3) returning id"#,
            user_id,
            token_hash,
            expires_at,
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(fila.id)
    }

    async fn buscar_vigente_por_hash(&self, token_hash: &[u8]) -> Result<Option<ResetToken>, RepoError> {
        let fila = sqlx::query!(
            r#"
            select id, user_id, token_hash, expires_at, consumed_at, email_code_hash, email_code_expires_at
            from recovery_reset_tokens
            where token_hash = $1 and consumed_at is null and expires_at > now()
            "#,
            token_hash,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(fila.map(|f| {
            fila_a_token(f.id, f.user_id, f.token_hash, f.expires_at, f.consumed_at, f.email_code_hash, f.email_code_expires_at)
        }))
    }

    async fn buscar_vigente(&self, id: Uuid) -> Result<Option<ResetToken>, RepoError> {
        let fila = sqlx::query!(
            r#"
            select id, user_id, token_hash, expires_at, consumed_at, email_code_hash, email_code_expires_at
            from recovery_reset_tokens
            where id = $1 and consumed_at is null and expires_at > now()
            "#,
            id,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(fila.map(|f| {
            fila_a_token(f.id, f.user_id, f.token_hash, f.expires_at, f.consumed_at, f.email_code_hash, f.email_code_expires_at)
        }))
    }

    async fn guardar_codigo_email(
        &self,
        id: Uuid,
        code_hash: &[u8],
        expires_at: OffsetDateTime,
    ) -> Result<(), RepoError> {
        sqlx::query!(
            r#"update recovery_reset_tokens set email_code_hash = $2, email_code_expires_at = $3 where id = $1"#,
            id,
            code_hash,
            expires_at,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn marcar_consumido(&self, id: Uuid) -> Result<bool, RepoError> {
        let resultado = sqlx::query!(
            r#"update recovery_reset_tokens set consumed_at = now() where id = $1 and consumed_at is null"#,
            id,
        )
        .execute(&self.pool)
        .await?;
        Ok(resultado.rows_affected() == 1)
    }
}
