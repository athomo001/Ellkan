// Autor: Athan Espinoza

//! Segunda implementación (SQLite, modo escritorio) de los repositorios de
//! `auth` — spec/13 §4/§16. Diferencias deliberadas respecto de la versión
//! Postgres, confirmadas con el usuario antes de escribir esto:
//!
//! - **Sin `role_id`**: el módulo de roles se compila afuera en este modo
//!   (spec/13 §16, "el rol es vestigial") — la tabla `users` recortada ni
//!   tiene la columna, `crear()` no consulta `roles`.
//! - **`buscar_por_prefijo`/`buscar_por_email_visible`** (búsqueda de OTROS
//!   usuarios para compartir): en modo escritorio de 1 solo usuario no hay a
//!   quién buscar. `buscar_por_prefijo` es un stub que siempre devuelve
//!   vacío; `buscar_por_email_visible` sólo "encuentra" al propio actor
//!   (nunca a otro), sin ninguna de las cláusulas de visibilidad por
//!   grupo/rol de la versión Postgres — colapsan a nada con 0 grupos.

use sqlx::{Row, SqlitePool};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::desktop::sqlite_util::{fmt_dt, parse_dt, parse_uuid};
use crate::error::RepoError;

use crate::auth::models::{DeviceChallengeRow, EmailVerificationRow, MaterialDesbloqueo, NuevoUsuario, Session, User, UserKeysRow, UsuarioBusqueda};
use crate::auth::repository::{
    AuthChallengeRepository, DeviceChallengeRepository, EmailVerificationRepository, KnownDeviceRepository,
    SessionRepository, UserRepository,
};

fn fila_a_user(row: &sqlx::sqlite::SqliteRow) -> Result<User, RepoError> {
    Ok(User {
        id: parse_uuid(row.try_get::<String, _>("id")?.as_str())?,
        security_stamp: parse_uuid(row.try_get::<String, _>("security_stamp")?.as_str())?,
        created_at: parse_dt(row.try_get::<String, _>("created_at")?.as_str())?,
        must_change_passphrase: row.try_get("must_change_passphrase")?,
    })
}

#[derive(Clone)]
pub struct SqliteUserRepository {
    pub pool: SqlitePool,
}

impl SqliteUserRepository {
    /// Punto 8 (recuperación local sin SMTP): reemplaza el blob de la clave
    /// privada tras un reset con el recovery kit y rota el `security_stamp`
    /// en la misma transacción, lo que invalida de una vez todas las
    /// sesiones abiertas de la cuenta (mismo mecanismo que el cambio de
    /// passphrase del modo servidor). `Ok(false)` si el usuario no existe.
    pub async fn reemplazar_clave_por_recuperacion(
        &self,
        user_id: Uuid,
        blob: &[u8],
        nonce: &[u8],
        salt: &[u8],
    ) -> Result<bool, RepoError> {
        let mut tx = self.pool.begin().await?;

        let actualizada =
            sqlx::query("update user_keys set encrypted_private_key_blob = ?2, private_key_nonce = ?3, kdf_salt = ?4 where user_id = ?1")
                .bind(user_id.to_string())
                .bind(blob)
                .bind(nonce)
                .bind(salt)
                .execute(&mut *tx)
                .await?;
        if actualizada.rows_affected() == 0 {
            return Ok(false);
        }

        sqlx::query("update users set security_stamp = ?2 where id = ?1")
            .bind(user_id.to_string())
            .bind(Uuid::now_v7().to_string())
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(true)
    }

    /// Punto 6 de la lista de pendientes de escritorio: cambiar el correo de
    /// la cuenta local (única) para poder alinearlo después con el de una
    /// cuenta del servidor. Método inherente, no del trait `UserRepository`
    /// compartido con Postgres — en modo servidor el correo es identidad de
    /// una cuenta multiusuario y no se cambia así.
    ///
    /// El correo es el AAD del blob de la clave privada (`user_keys`): si sólo
    /// cambiara la fila de `users`, la cuenta quedaría imposible de
    /// desbloquear. Por eso el cliente manda el blob ya re-sellado con el
    /// correo nuevo y las dos escrituras van en una sola transacción — o se
    /// aplican las dos o ninguna. `RepoError::Conflict` si el correo ya lo
    /// usa otro usuario; `Ok(false)` si el usuario no existe.
    pub async fn actualizar_email_y_blob(
        &self,
        user_id: Uuid,
        nuevo_email: &str,
        blob: &[u8],
        nonce: &[u8],
        salt: &[u8],
    ) -> Result<bool, RepoError> {
        let mut tx = self.pool.begin().await?;

        let resultado = sqlx::query("update users set email = ?2 where id = ?1 and deleted_at is null")
            .bind(user_id.to_string())
            .bind(nuevo_email)
            .execute(&mut *tx)
            .await;

        if let Err(sqlx::Error::Database(db)) = &resultado
            && db.is_unique_violation()
        {
            return Err(RepoError::Conflict);
        }
        if resultado?.rows_affected() == 0 {
            return Ok(false);
        }

        sqlx::query("update user_keys set encrypted_private_key_blob = ?2, private_key_nonce = ?3, kdf_salt = ?4 where user_id = ?1")
            .bind(user_id.to_string())
            .bind(blob)
            .bind(nonce)
            .bind(salt)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(true)
    }
}

impl UserRepository for SqliteUserRepository {
    async fn crear(&self, nuevo: NuevoUsuario<'_>, ya_verificado: bool) -> Result<User, RepoError> {
        let mut tx = self.pool.begin().await?;

        // Mismo criterio de bootstrap que la versión Postgres: el primer
        // usuario de toda la instancia nace ya verificado sin importar
        // `ya_verificado` — en modo escritorio esto en la práctica siempre
        // es el único usuario que va a existir (spec/13 §16).
        let existe_alguno: bool =
            sqlx::query_scalar("select exists(select 1 from users)").fetch_one(&mut *tx).await?;
        let nace_verificado = !existe_alguno || ya_verificado;

        let id = Uuid::now_v7();
        let security_stamp = Uuid::now_v7();
        let ahora = OffsetDateTime::now_utc();
        let email_verified_at = nace_verificado.then(|| fmt_dt(ahora));

        let resultado = sqlx::query(
            r#"insert into users (id, email, display_name, security_stamp, email_verified_at, created_at)
               values (?1, ?2, ?3, ?4, ?5, ?6)"#,
        )
        .bind(id.to_string())
        .bind(nuevo.email)
        .bind(nuevo.display_name)
        .bind(security_stamp.to_string())
        .bind(email_verified_at)
        .bind(fmt_dt(ahora))
        .execute(&mut *tx)
        .await;

        if let Err(sqlx::Error::Database(db)) = &resultado
            && db.is_unique_violation()
        {
            return Err(RepoError::Conflict);
        }
        resultado?;

        sqlx::query(
            r#"insert into user_keys (
                user_id, public_key_x25519, public_key_ed25519,
                encrypted_private_key_blob, private_key_nonce, kdf_salt
            ) values (?1, ?2, ?3, ?4, ?5, ?6)"#,
        )
        .bind(id.to_string())
        .bind(nuevo.public_key_x25519)
        .bind(nuevo.public_key_ed25519)
        .bind(nuevo.encrypted_private_key_blob)
        .bind(nuevo.private_key_nonce)
        .bind(nuevo.kdf_salt)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(User { id, security_stamp, created_at: ahora, must_change_passphrase: false })
    }

    async fn buscar_por_email(&self, email: &str) -> Result<Option<User>, RepoError> {
        let fila = sqlx::query(
            r#"select id, security_stamp, created_at, must_change_passphrase from users
               where email = ?1 and active and deleted_at is null and email_verified_at is not null"#,
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;
        fila.as_ref().map(fila_a_user).transpose()
    }

    async fn buscar_por_id(&self, user_id: Uuid) -> Result<Option<User>, RepoError> {
        let fila = sqlx::query(
            r#"select id, security_stamp, created_at, must_change_passphrase from users
               where id = ?1 and active and deleted_at is null and email_verified_at is not null"#,
        )
        .bind(user_id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        fila.as_ref().map(fila_a_user).transpose()
    }

    async fn marcar_debe_cambiar_passphrase(&self, user_id: Uuid) -> Result<(), RepoError> {
        sqlx::query(r#"update users set must_change_passphrase = 1 where id = ?1"#)
            .bind(user_id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn buscar_keys(&self, user_id: Uuid) -> Result<Option<UserKeysRow>, RepoError> {
        let fila = sqlx::query(r#"select public_key_x25519, public_key_ed25519 from user_keys where user_id = ?1"#)
            .bind(user_id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        Ok(fila.map(|f| UserKeysRow {
            public_key_x25519: f.get("public_key_x25519"),
            public_key_ed25519: f.get("public_key_ed25519"),
        }))
    }

    async fn email_y_nombre(&self, user_id: Uuid) -> Result<Option<(String, String)>, RepoError> {
        let fila = sqlx::query(
            r#"select email, display_name from users
               where id = ?1 and active and deleted_at is null and email_verified_at is not null"#,
        )
        .bind(user_id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        Ok(fila.map(|f| (f.get("email"), f.get("display_name"))))
    }

    async fn material_desbloqueo_por_email(&self, email: &str) -> Result<Option<MaterialDesbloqueo>, RepoError> {
        let fila = sqlx::query(
            r#"select uk.encrypted_private_key_blob, uk.private_key_nonce, uk.kdf_salt
               from user_keys uk join users u on u.id = uk.user_id
               where u.email = ?1 and u.active and u.deleted_at is null and u.email_verified_at is not null"#,
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;
        Ok(fila.map(|f| MaterialDesbloqueo {
            encrypted_private_key_blob: f.get("encrypted_private_key_blob"),
            private_key_nonce: f.get("private_key_nonce"),
            kdf_salt: f.get("kdf_salt"),
        }))
    }

    async fn existe_alguno(&self) -> Result<bool, RepoError> {
        Ok(sqlx::query_scalar("select exists(select 1 from users)").fetch_one(&self.pool).await?)
    }

    async fn buscar_no_verificado_por_email(&self, email: &str) -> Result<Option<User>, RepoError> {
        let fila = sqlx::query(
            r#"select id, security_stamp, created_at, must_change_passphrase from users
               where email = ?1 and active and deleted_at is null and email_verified_at is null"#,
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;
        fila.as_ref().map(fila_a_user).transpose()
    }

    /// Modo escritorio: 1 solo usuario, sin nadie más a quien buscar para
    /// compartir — stub, siempre vacío (decisión confirmada con el usuario).
    async fn buscar_por_prefijo(&self, _actor_id: Uuid, _prefijo: &str, _limite: i64) -> Result<Vec<UsuarioBusqueda>, RepoError> {
        Ok(Vec::new())
    }

    /// Modo escritorio: sólo "visible" si es el propio actor buscándose a sí
    /// mismo — ninguna de las cláusulas de visibilidad por grupo/rol de la
    /// versión Postgres aplica con 0 grupos (decisión confirmada).
    async fn buscar_por_email_visible(&self, actor_id: Uuid, email: &str) -> Result<Option<User>, RepoError> {
        let fila = sqlx::query(
            r#"select id, security_stamp, created_at, must_change_passphrase from users
               where email = ?1 and id = ?2 and active and deleted_at is null and email_verified_at is not null"#,
        )
        .bind(email)
        .bind(actor_id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        fila.as_ref().map(fila_a_user).transpose()
    }
}

impl EmailVerificationRepository for SqliteUserRepository {
    async fn crear(&self, user_id: Uuid, code_hash: &[u8], expires_at: OffsetDateTime) -> Result<Uuid, RepoError> {
        let id = Uuid::now_v7();
        sqlx::query(
            r#"insert into email_verification_challenges (id, user_id, code_hash, expires_at)
               values (?1, ?2, ?3, ?4)"#,
        )
        .bind(id.to_string())
        .bind(user_id.to_string())
        .bind(code_hash)
        .bind(fmt_dt(expires_at))
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    async fn buscar_pendiente_por_usuario(&self, user_id: Uuid) -> Result<Option<EmailVerificationRow>, RepoError> {
        let fila = sqlx::query(
            r#"select id, user_id, code_hash from email_verification_challenges
               where user_id = ?1 and consumed_at is null and expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
               order by id desc limit 1"#,
        )
        .bind(user_id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        fila.map(|f| -> Result<_, RepoError> {
            Ok(EmailVerificationRow {
                id: parse_uuid(f.try_get::<String, _>("id")?.as_str())?,
                user_id: parse_uuid(f.try_get::<String, _>("user_id")?.as_str())?,
                code_hash: f.get("code_hash"),
            })
        })
        .transpose()
    }

    async fn consumir(&self, id: Uuid) -> Result<(), RepoError> {
        sqlx::query(r#"update email_verification_challenges set consumed_at = ?2 where id = ?1"#)
            .bind(id.to_string())
            .bind(fmt_dt(OffsetDateTime::now_utc()))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn invalidar_pendientes_de_usuario(&self, user_id: Uuid) -> Result<(), RepoError> {
        sqlx::query(
            r#"update email_verification_challenges set consumed_at = ?2
               where user_id = ?1 and consumed_at is null"#,
        )
        .bind(user_id.to_string())
        .bind(fmt_dt(OffsetDateTime::now_utc()))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn marcar_verificado(&self, user_id: Uuid) -> Result<(), RepoError> {
        sqlx::query(r#"update users set email_verified_at = ?2 where id = ?1"#)
            .bind(user_id.to_string())
            .bind(fmt_dt(OffsetDateTime::now_utc()))
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

impl crate::notificaciones::LocaleRepository for SqliteUserRepository {
    async fn locale_de_email(&self, email: &str) -> Result<Option<String>, RepoError> {
        let fila = sqlx::query(r#"select locale from users where email = ?1"#)
            .bind(email)
            .fetch_optional(&self.pool)
            .await?;
        Ok(fila.map(|f| f.get("locale")))
    }
}

#[derive(Clone)]
pub struct SqliteAuthChallengeRepository {
    pub pool: SqlitePool,
}

impl AuthChallengeRepository for SqliteAuthChallengeRepository {
    async fn guardar_challenge(&self, user_id: Uuid, nonce: &[u8], expires_at: OffsetDateTime) -> Result<(), RepoError> {
        sqlx::query(r#"insert into auth_challenges (id, user_id, nonce, expires_at) values (?1, ?2, ?3, ?4)"#)
            .bind(Uuid::now_v7().to_string())
            .bind(user_id.to_string())
            .bind(nonce)
            .bind(fmt_dt(expires_at))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn consumir_challenge(&self, user_id: Uuid, nonce: &[u8]) -> Result<bool, RepoError> {
        let resultado = sqlx::query(
            r#"update auth_challenges set consumed_at = ?3
               where user_id = ?1 and nonce = ?2
                 and consumed_at is null and expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')"#,
        )
        .bind(user_id.to_string())
        .bind(nonce)
        .bind(fmt_dt(OffsetDateTime::now_utc()))
        .execute(&self.pool)
        .await?;
        Ok(resultado.rows_affected() == 1)
    }
}

#[derive(Clone)]
pub struct SqliteSessionRepository {
    pub pool: SqlitePool,
}

impl SqliteSessionRepository {
    async fn crear_con(&self, user_id: Uuid, security_stamp: Uuid, mfa_verificada: bool) -> Result<Session, RepoError> {
        let id = Uuid::now_v7();
        let ahora = OffsetDateTime::now_utc();
        let expires_at = ahora + time::Duration::hours(12);
        sqlx::query(
            r#"insert into sessions (id, user_id, security_stamp, mfa_verified_at, expires_at)
               values (?1, ?2, ?3, ?4, ?5)"#,
        )
        .bind(id.to_string())
        .bind(user_id.to_string())
        .bind(security_stamp.to_string())
        .bind(mfa_verificada.then(|| fmt_dt(ahora)))
        .bind(fmt_dt(expires_at))
        .execute(&self.pool)
        .await?;
        Ok(Session { id, user_id })
    }
}

impl SessionRepository for SqliteSessionRepository {
    async fn crear(&self, user_id: Uuid, security_stamp: Uuid) -> Result<Session, RepoError> {
        self.crear_con(user_id, security_stamp, true).await
    }

    async fn crear_parcial(&self, user_id: Uuid, security_stamp: Uuid) -> Result<Session, RepoError> {
        self.crear_con(user_id, security_stamp, false).await
    }

    async fn validar(&self, session_id: Uuid) -> Result<Option<Uuid>, RepoError> {
        let fila = sqlx::query(
            r#"select s.user_id as user_id from sessions s join users u on u.id = s.user_id
               where s.id = ?1 and s.revoked_at is null
                 and s.expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 and s.security_stamp = u.security_stamp and s.mfa_verified_at is not null
                 and u.active and u.deleted_at is null and u.email_verified_at is not null"#,
        )
        .bind(session_id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        fila.map(|f| parse_uuid(f.try_get::<String, _>("user_id")?.as_str())).transpose()
    }

    async fn validar_cualquiera(&self, session_id: Uuid) -> Result<Option<Uuid>, RepoError> {
        let fila = sqlx::query(
            r#"select s.user_id as user_id from sessions s join users u on u.id = s.user_id
               where s.id = ?1 and s.revoked_at is null
                 and s.expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 and s.security_stamp = u.security_stamp
                 and u.active and u.deleted_at is null and u.email_verified_at is not null"#,
        )
        .bind(session_id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        fila.map(|f| parse_uuid(f.try_get::<String, _>("user_id")?.as_str())).transpose()
    }

    async fn marcar_mfa_verificada(&self, session_id: Uuid) -> Result<(), RepoError> {
        sqlx::query(r#"update sessions set mfa_verified_at = ?2 where id = ?1 and mfa_verified_at is null"#)
            .bind(session_id.to_string())
            .bind(fmt_dt(OffsetDateTime::now_utc()))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn revocar(&self, session_id: Uuid) -> Result<(), RepoError> {
        sqlx::query(r#"update sessions set revoked_at = ?2 where id = ?1 and revoked_at is null"#)
            .bind(session_id.to_string())
            .bind(fmt_dt(OffsetDateTime::now_utc()))
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct SqliteKnownDeviceRepository {
    pub pool: SqlitePool,
}

impl KnownDeviceRepository for SqliteKnownDeviceRepository {
    async fn es_conocido(&self, user_id: Uuid, device_token_hash: &[u8]) -> Result<bool, RepoError> {
        let fila = sqlx::query(r#"select 1 as x from known_devices where user_id = ?1 and device_token_hash = ?2"#)
            .bind(user_id.to_string())
            .bind(device_token_hash)
            .fetch_optional(&self.pool)
            .await?;
        Ok(fila.is_some())
    }

    async fn marcar_conocido(&self, user_id: Uuid, device_token_hash: &[u8]) -> Result<(), RepoError> {
        sqlx::query(
            r#"insert into known_devices (user_id, device_token_hash, last_seen_at) values (?1, ?2, ?3)
               on conflict(user_id, device_token_hash) do update set last_seen_at = excluded.last_seen_at"#,
        )
        .bind(user_id.to_string())
        .bind(device_token_hash)
        .bind(fmt_dt(OffsetDateTime::now_utc()))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn mfa_confirmado(&self, user_id: Uuid, device_token_hash: &[u8]) -> Result<bool, RepoError> {
        let fila = sqlx::query(
            r#"select 1 as x from known_devices
               where user_id = ?1 and device_token_hash = ?2 and mfa_verified_at is not null"#,
        )
        .bind(user_id.to_string())
        .bind(device_token_hash)
        .fetch_optional(&self.pool)
        .await?;
        Ok(fila.is_some())
    }

    async fn marcar_mfa_confirmado(&self, user_id: Uuid, device_token_hash: &[u8]) -> Result<(), RepoError> {
        sqlx::query(r#"update known_devices set mfa_verified_at = ?3 where user_id = ?1 and device_token_hash = ?2"#)
            .bind(user_id.to_string())
            .bind(device_token_hash)
            .bind(fmt_dt(OffsetDateTime::now_utc()))
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct SqliteDeviceChallengeRepository {
    pub pool: SqlitePool,
}

impl DeviceChallengeRepository for SqliteDeviceChallengeRepository {
    async fn crear(
        &self,
        user_id: Uuid,
        device_token_hash: &[u8],
        code_hash: &[u8],
        expires_at: OffsetDateTime,
    ) -> Result<Uuid, RepoError> {
        let id = Uuid::now_v7();
        sqlx::query(
            r#"insert into device_challenges (id, user_id, device_token_hash, code_hash, expires_at)
               values (?1, ?2, ?3, ?4, ?5)"#,
        )
        .bind(id.to_string())
        .bind(user_id.to_string())
        .bind(device_token_hash)
        .bind(code_hash)
        .bind(fmt_dt(expires_at))
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    async fn buscar_pendiente(&self, id: Uuid) -> Result<Option<DeviceChallengeRow>, RepoError> {
        let fila = sqlx::query(
            r#"select id, user_id, device_token_hash, code_hash from device_challenges
               where id = ?1 and consumed_at is null and expires_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now')"#,
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        fila.map(|f| -> Result<_, RepoError> {
            Ok(DeviceChallengeRow {
                id: parse_uuid(f.try_get::<String, _>("id")?.as_str())?,
                user_id: parse_uuid(f.try_get::<String, _>("user_id")?.as_str())?,
                device_token_hash: f.get("device_token_hash"),
                code_hash: f.get("code_hash"),
            })
        })
        .transpose()
    }

    async fn consumir(&self, id: Uuid) -> Result<(), RepoError> {
        sqlx::query(r#"update device_challenges set consumed_at = ?2 where id = ?1"#)
            .bind(id.to_string())
            .bind(fmt_dt(OffsetDateTime::now_utc()))
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
