// Autor: Athan Espinoza

#![allow(async_fn_in_trait)]

use time::OffsetDateTime;
use uuid::Uuid;
use webauthn_rs::prelude::Passkey as WebauthnPasskey;

use crate::error::RepoError;

use super::models::PasskeyRow;

pub trait PasskeyRepository {
    #[allow(clippy::too_many_arguments)]
    async fn insertar(
        &self,
        id: Uuid,
        user_id: Uuid,
        credential_id: &[u8],
        passkey_data: &WebauthnPasskey,
        prf_wrapped_private_key: Option<&[u8]>,
        label: Option<&str>,
    ) -> Result<(), RepoError>;

    async fn listar_de(&self, user_id: Uuid) -> Result<Vec<PasskeyRow>, RepoError>;

    /// Post-autenticación: nuevo estado del `Passkey` (contador, flags de
    /// backup) + `last_used_at` — buscado por `credential_id`, que
    /// `AuthenticationResult::cred_id()` ya identifica sin ambigüedad.
    async fn actualizar_tras_auth(
        &self,
        credential_id: &[u8],
        passkey_data: &WebauthnPasskey,
    ) -> Result<(), RepoError>;
}

/// Estado efímero de una ceremonia WebAuthn — un solo uso: `tomar` borra la
/// fila al leerla (equivalente a `auth_challenges.consumed_at`, pero acá se
/// borra en vez de marcarse, porque no hay ninguna razón para conservar el
/// estado de una ceremonia ya terminada).
pub trait CeremonyStateRepository {
    async fn guardar(
        &self,
        user_id: Uuid,
        kind: &str,
        state_json: serde_json::Value,
        expires_at: OffsetDateTime,
    ) -> Result<(), RepoError>;

    async fn tomar(&self, user_id: Uuid, kind: &str) -> Result<Option<serde_json::Value>, RepoError>;
}

#[derive(Clone)]
pub struct PgPasskeyRepository {
    pub pool: sqlx::PgPool,
}

impl PasskeyRepository for PgPasskeyRepository {
    async fn insertar(
        &self,
        id: Uuid,
        user_id: Uuid,
        credential_id: &[u8],
        passkey_data: &WebauthnPasskey,
        prf_wrapped_private_key: Option<&[u8]>,
        label: Option<&str>,
    ) -> Result<(), RepoError> {
        let data = serde_json::to_value(passkey_data).expect("Passkey siempre serializa a JSON válido");
        sqlx::query!(
            r#"
            insert into passkeys (id, user_id, credential_id, passkey_data, prf_wrapped_private_key, label)
            values ($1, $2, $3, $4, $5, $6)
            "#,
            id,
            user_id,
            credential_id,
            data,
            prf_wrapped_private_key,
            label,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => RepoError::Conflict,
            _ => RepoError::Database(e),
        })?;
        Ok(())
    }

    async fn listar_de(&self, user_id: Uuid) -> Result<Vec<PasskeyRow>, RepoError> {
        let filas = sqlx::query!(
            r#"
            select id, user_id, passkey_data, prf_wrapped_private_key, last_used_at
            from passkeys where user_id = $1
            "#,
            user_id,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(filas
            .into_iter()
            .map(|f| PasskeyRow {
                id: f.id,
                user_id: f.user_id,
                passkey_data: serde_json::from_value(f.passkey_data)
                    .expect("passkey_data persistido siempre es un Passkey válido"),
                prf_wrapped_private_key: f.prf_wrapped_private_key,
                last_used_at: f.last_used_at,
            })
            .collect())
    }

    async fn actualizar_tras_auth(
        &self,
        credential_id: &[u8],
        passkey_data: &WebauthnPasskey,
    ) -> Result<(), RepoError> {
        let data = serde_json::to_value(passkey_data).expect("Passkey siempre serializa a JSON válido");
        sqlx::query!(
            r#"update passkeys set passkey_data = $2, last_used_at = now() where credential_id = $1"#,
            credential_id,
            data,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct PgCeremonyStateRepository {
    pub pool: sqlx::PgPool,
}

impl CeremonyStateRepository for PgCeremonyStateRepository {
    async fn guardar(
        &self,
        user_id: Uuid,
        kind: &str,
        state_json: serde_json::Value,
        expires_at: OffsetDateTime,
    ) -> Result<(), RepoError> {
        sqlx::query!(
            r#"
            insert into webauthn_ceremony_state (user_id, kind, state_json, expires_at)
            values ($1, $2, $3, $4)
            on conflict (user_id, kind) do update
                set state_json = excluded.state_json, expires_at = excluded.expires_at
            "#,
            user_id,
            kind,
            state_json,
            expires_at,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn tomar(&self, user_id: Uuid, kind: &str) -> Result<Option<serde_json::Value>, RepoError> {
        let fila = sqlx::query!(
            r#"
            delete from webauthn_ceremony_state
            where user_id = $1 and kind = $2 and expires_at > now()
            returning state_json
            "#,
            user_id,
            kind,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(fila.map(|f| f.state_json))
    }
}
