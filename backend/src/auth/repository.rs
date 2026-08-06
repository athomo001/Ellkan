// Autor: Athan Espinoza

//! Repository de auth — trait consumido por el Service (nunca un struct
//! concreto en la firma), única implementación real sobre `sqlx::PgPool`.
//!
//! `async fn` en estos traits es intencional: se usan sólo dentro de este
//! crate (genéricos, no `dyn`), así que la falta de bounds explícitos de
//! `Send` en la firma del trait no es un problema real.
#![allow(async_fn_in_trait)]

use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::RepoError;

use super::models::{DeviceChallengeRow, NuevoUsuario, Session, User, UserKeysRow};

pub trait UserRepository {
    async fn crear(&self, nuevo: NuevoUsuario<'_>) -> Result<User, RepoError>;
    async fn buscar_por_email(&self, email: &str) -> Result<Option<User>, RepoError>;
    async fn buscar_por_id(&self, user_id: Uuid) -> Result<Option<User>, RepoError>;
    async fn buscar_keys(&self, user_id: Uuid) -> Result<Option<UserKeysRow>, RepoError>;

    /// F-03: `webauthn-rs` exige `email`/`display_name` al iniciar el
    /// registro de una passkey — no hace falta en el resto del módulo, que
    /// sólo trabaja con `id`+`security_stamp`.
    async fn email_y_nombre(&self, user_id: Uuid) -> Result<Option<(String, String)>, RepoError>;

    /// F-01 (frontend web): material de desbloqueo por email — nunca la
    /// clave privada en claro, sólo lo que ya vive en `user_keys`.
    async fn material_desbloqueo_por_email(&self, email: &str) -> Result<Option<super::models::MaterialDesbloqueo>, RepoError>;
}

pub trait AuthChallengeRepository {
    async fn guardar_challenge(
        &self,
        user_id: Uuid,
        nonce: &[u8],
        expires_at: OffsetDateTime,
    ) -> Result<(), RepoError>;

    /// Consume un challenge válido (existente, no vencido, no usado) para
    /// `user_id`+`nonce` — devuelve `true` si había uno y se consumió.
    async fn consumir_challenge(&self, user_id: Uuid, nonce: &[u8]) -> Result<bool, RepoError>;
}

pub trait SessionRepository {
    /// Sesión completa — `mfa_verified_at` se fija de inmediato porque el
    /// login no requería (o ya satisfizo) un segundo factor.
    async fn crear(&self, user_id: Uuid, security_stamp: Uuid) -> Result<Session, RepoError>;

    /// F-14: sesión parcial — `mfa_verified_at` queda `null` hasta que
    /// `mfa::service` la marque completa (verificando un código, o
    /// confirmando un TOTP nuevo en el flujo "configura tu MFA ahora").
    async fn crear_parcial(&self, user_id: Uuid, security_stamp: Uuid) -> Result<Session, RepoError>;

    /// Válida para operar sobre el resto de la API: no revocada, no vencida,
    /// `security_stamp` vigente, **y MFA ya verificado**. Rotar el stamp
    /// invalida todas las sesiones de un usuario de una sola vez, sin
    /// iterar ni marcar cada fila.
    async fn validar(&self, session_id: Uuid) -> Result<Option<Uuid>, RepoError>;

    /// Igual que `validar` pero sin exigir `mfa_verified_at` — la única
    /// franja de la API donde una sesión parcial es válida: verificar el
    /// código MFA o configurar el segundo factor por primera vez (F-14).
    async fn validar_cualquiera(&self, session_id: Uuid) -> Result<Option<Uuid>, RepoError>;

    /// Cierra el estado parcial de una sesión — la deja utilizable por el
    /// resto de la API (F-14).
    async fn marcar_mfa_verificada(&self, session_id: Uuid) -> Result<(), RepoError>;

    async fn revocar(&self, session_id: Uuid) -> Result<(), RepoError>;
}

pub trait KnownDeviceRepository {
    async fn es_conocido(&self, user_id: Uuid, device_token_hash: &[u8]) -> Result<bool, RepoError>;
    async fn marcar_conocido(&self, user_id: Uuid, device_token_hash: &[u8]) -> Result<(), RepoError>;
}

pub trait DeviceChallengeRepository {
    async fn crear(
        &self,
        user_id: Uuid,
        device_token_hash: &[u8],
        code_hash: &[u8],
        expires_at: OffsetDateTime,
    ) -> Result<Uuid, RepoError>;

    /// Trae un desafío pendiente (no vencido, no consumido) por id — la
    /// comparación del código contra `code_hash` es responsabilidad del
    /// caller, en tiempo constante, nunca en SQL.
    async fn buscar_pendiente(&self, id: Uuid) -> Result<Option<DeviceChallengeRow>, RepoError>;

    async fn consumir(&self, id: Uuid) -> Result<(), RepoError>;
}

#[derive(Clone)]
pub struct PgUserRepository {
    pub pool: sqlx::PgPool,
}

impl UserRepository for PgUserRepository {
    async fn crear(&self, nuevo: NuevoUsuario<'_>) -> Result<User, RepoError> {
        let mut tx = self.pool.begin().await?;
        // El auto-registro (`POST /auth/register`) siempre nace con el rol
        // `user` — promover a admin es una acción deliberada aparte (CLI
        // `admin promote-to-admin`/`create-user --role admin`, F-41), nunca
        // algo que el propio request de registro pueda elegir.
        let fila = sqlx::query!(
            r#"
            insert into users (email, display_name, role_id)
            values ($1, $2, (select id from roles where name = 'user'))
            returning id, security_stamp, created_at
            "#,
            nuevo.email,
            nuevo.display_name,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => RepoError::Conflict,
            _ => RepoError::Database(e),
        })?;

        sqlx::query!(
            r#"
            insert into user_keys (
                user_id, public_key_x25519, public_key_ed25519,
                encrypted_private_key_blob, private_key_nonce, kdf_salt
            )
            values ($1, $2, $3, $4, $5, $6)
            "#,
            fila.id,
            nuevo.public_key_x25519,
            nuevo.public_key_ed25519,
            nuevo.encrypted_private_key_blob,
            nuevo.private_key_nonce,
            nuevo.kdf_salt,
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(User { id: fila.id, security_stamp: fila.security_stamp, created_at: fila.created_at })
    }

    async fn buscar_por_email(&self, email: &str) -> Result<Option<User>, RepoError> {
        let fila = sqlx::query!(
            r#"select id, security_stamp, created_at from users
               where email = $1 and active and deleted_at is null"#,
            email,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(fila.map(|f| User { id: f.id, security_stamp: f.security_stamp, created_at: f.created_at }))
    }

    async fn buscar_por_id(&self, user_id: Uuid) -> Result<Option<User>, RepoError> {
        let fila = sqlx::query!(
            r#"select id, security_stamp, created_at from users
               where id = $1 and active and deleted_at is null"#,
            user_id,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(fila.map(|f| User { id: f.id, security_stamp: f.security_stamp, created_at: f.created_at }))
    }

    async fn buscar_keys(&self, user_id: Uuid) -> Result<Option<UserKeysRow>, RepoError> {
        let fila = sqlx::query!(
            r#"select public_key_x25519, public_key_ed25519 from user_keys where user_id = $1"#,
            user_id,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(fila.map(|f| UserKeysRow {
            public_key_x25519: f.public_key_x25519,
            public_key_ed25519: f.public_key_ed25519,
        }))
    }

    async fn email_y_nombre(&self, user_id: Uuid) -> Result<Option<(String, String)>, RepoError> {
        let fila = sqlx::query!(
            r#"select email, display_name from users where id = $1 and active and deleted_at is null"#,
            user_id,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(fila.map(|f| (f.email, f.display_name)))
    }

    async fn material_desbloqueo_por_email(
        &self,
        email: &str,
    ) -> Result<Option<super::models::MaterialDesbloqueo>, RepoError> {
        let fila = sqlx::query!(
            r#"
            select uk.encrypted_private_key_blob, uk.private_key_nonce, uk.kdf_salt
            from user_keys uk
            join users u on u.id = uk.user_id
            where u.email = $1 and u.active and u.deleted_at is null
            "#,
            email,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(fila.map(|f| super::models::MaterialDesbloqueo {
            encrypted_private_key_blob: f.encrypted_private_key_blob,
            private_key_nonce: f.private_key_nonce,
            kdf_salt: f.kdf_salt,
        }))
    }
}

#[derive(Clone)]
pub struct PgAuthChallengeRepository {
    pub pool: sqlx::PgPool,
}

impl AuthChallengeRepository for PgAuthChallengeRepository {
    async fn guardar_challenge(
        &self,
        user_id: Uuid,
        nonce: &[u8],
        expires_at: OffsetDateTime,
    ) -> Result<(), RepoError> {
        sqlx::query!(
            r#"insert into auth_challenges (user_id, nonce, expires_at) values ($1, $2, $3)"#,
            user_id,
            nonce,
            expires_at,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn consumir_challenge(&self, user_id: Uuid, nonce: &[u8]) -> Result<bool, RepoError> {
        let resultado = sqlx::query!(
            r#"
            update auth_challenges set consumed_at = now()
            where user_id = $1 and nonce = $2
              and consumed_at is null and expires_at > now()
            "#,
            user_id,
            nonce,
        )
        .execute(&self.pool)
        .await?;
        Ok(resultado.rows_affected() == 1)
    }
}

#[derive(Clone)]
pub struct PgSessionRepository {
    pub pool: sqlx::PgPool,
}

impl SessionRepository for PgSessionRepository {
    async fn crear(&self, user_id: Uuid, security_stamp: Uuid) -> Result<Session, RepoError> {
        let fila = sqlx::query!(
            r#"
            insert into sessions (user_id, security_stamp, mfa_verified_at, expires_at)
            values ($1, $2, now(), now() + interval '12 hours')
            returning id, user_id
            "#,
            user_id,
            security_stamp,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(Session { id: fila.id, user_id: fila.user_id })
    }

    async fn crear_parcial(&self, user_id: Uuid, security_stamp: Uuid) -> Result<Session, RepoError> {
        let fila = sqlx::query!(
            r#"
            insert into sessions (user_id, security_stamp, mfa_verified_at, expires_at)
            values ($1, $2, null, now() + interval '12 hours')
            returning id, user_id
            "#,
            user_id,
            security_stamp,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(Session { id: fila.id, user_id: fila.user_id })
    }

    async fn validar(&self, session_id: Uuid) -> Result<Option<Uuid>, RepoError> {
        let fila = sqlx::query!(
            r#"
            select s.user_id
            from sessions s
            join users u on u.id = s.user_id
            where s.id = $1
              and s.revoked_at is null
              and s.expires_at > now()
              and s.security_stamp = u.security_stamp
              and s.mfa_verified_at is not null
              and u.active and u.deleted_at is null
            "#,
            session_id,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(fila.map(|f| f.user_id))
    }

    async fn validar_cualquiera(&self, session_id: Uuid) -> Result<Option<Uuid>, RepoError> {
        let fila = sqlx::query!(
            r#"
            select s.user_id
            from sessions s
            join users u on u.id = s.user_id
            where s.id = $1
              and s.revoked_at is null
              and s.expires_at > now()
              and s.security_stamp = u.security_stamp
              and u.active and u.deleted_at is null
            "#,
            session_id,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(fila.map(|f| f.user_id))
    }

    async fn marcar_mfa_verificada(&self, session_id: Uuid) -> Result<(), RepoError> {
        sqlx::query!(
            r#"update sessions set mfa_verified_at = now() where id = $1 and mfa_verified_at is null"#,
            session_id,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn revocar(&self, session_id: Uuid) -> Result<(), RepoError> {
        sqlx::query!(
            r#"update sessions set revoked_at = now() where id = $1 and revoked_at is null"#,
            session_id,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct PgKnownDeviceRepository {
    pub pool: sqlx::PgPool,
}

impl KnownDeviceRepository for PgKnownDeviceRepository {
    async fn es_conocido(&self, user_id: Uuid, device_token_hash: &[u8]) -> Result<bool, RepoError> {
        let fila = sqlx::query!(
            r#"select 1 as "existe!" from known_devices where user_id = $1 and device_token_hash = $2"#,
            user_id,
            device_token_hash,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(fila.is_some())
    }

    async fn marcar_conocido(&self, user_id: Uuid, device_token_hash: &[u8]) -> Result<(), RepoError> {
        sqlx::query!(
            r#"insert into known_devices (user_id, device_token_hash) values ($1, $2)
               on conflict (user_id, device_token_hash) do update set last_seen_at = now()"#,
            user_id,
            device_token_hash,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct PgDeviceChallengeRepository {
    pub pool: sqlx::PgPool,
}

impl DeviceChallengeRepository for PgDeviceChallengeRepository {
    async fn crear(
        &self,
        user_id: Uuid,
        device_token_hash: &[u8],
        code_hash: &[u8],
        expires_at: OffsetDateTime,
    ) -> Result<Uuid, RepoError> {
        let fila = sqlx::query!(
            r#"
            insert into device_challenges (user_id, device_token_hash, code_hash, expires_at)
            values ($1, $2, $3, $4)
            returning id
            "#,
            user_id,
            device_token_hash,
            code_hash,
            expires_at,
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(fila.id)
    }

    async fn buscar_pendiente(&self, id: Uuid) -> Result<Option<DeviceChallengeRow>, RepoError> {
        let fila = sqlx::query!(
            r#"select id, user_id, device_token_hash, code_hash from device_challenges
               where id = $1 and consumed_at is null and expires_at > now()"#,
            id,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(fila.map(|f| DeviceChallengeRow {
            id: f.id,
            user_id: f.user_id,
            device_token_hash: f.device_token_hash,
            code_hash: f.code_hash,
        }))
    }

    async fn consumir(&self, id: Uuid) -> Result<(), RepoError> {
        sqlx::query!(r#"update device_challenges set consumed_at = now() where id = $1"#, id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
