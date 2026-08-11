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

use super::models::{DeviceChallengeRow, EmailVerificationRow, NuevoUsuario, Session, User, UserKeysRow};

pub trait UserRepository {
    /// F-24: `ya_verificado` lo decide el caller, nunca esta capa — el
    /// bootstrap (primer usuario de la instancia) nace verificado sin
    /// importar el valor pasado (ver `PgUserRepository::crear`); un
    /// auto-registro normal pasa `false` (`AuthService::registrar`, tiene
    /// que verificar el email); un JIT provisioning de SSO pasa `true`
    /// (`sso::service`, el IdP ya vouched por el email — `email_verified`
    /// del token, no puede pasar de nuevo por la verificación de F-24).
    async fn crear(&self, nuevo: NuevoUsuario<'_>, ya_verificado: bool) -> Result<User, RepoError>;
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

    /// F-24: ¿ya existe algún usuario en la instancia? Decide si un
    /// registro es el bootstrap (nace ya verificado, sin pasar por
    /// self-registration-policy/SMTP) o uno normal.
    async fn existe_alguno(&self) -> Result<bool, RepoError>;

    /// F-24: como `buscar_por_email`, pero exige `email_verified_at is
    /// null` en vez de `is not null` — lo usa el flujo de verificación
    /// (verificar/reenviar), que por definición sólo tiene sentido para una
    /// cuenta que todavía no está verificada; ya verificada, se comporta
    /// como si no existiera (anti-enumeration en `reenviar_verificacion`).
    async fn buscar_no_verificado_por_email(&self, email: &str) -> Result<Option<User>, RepoError>;

    /// `GET /users/search?q=` — coincidencia parcial sobre email/display_name,
    /// para el buscador en vivo del modal de compartir (módulo 3/UX real).
    /// 2026-08-11: acotado a quién puede ver `actor_id` (F-11 — ver
    /// `visibilidad_de_usuarios` en `service.rs` para el criterio exacto).
    async fn buscar_por_prefijo(&self, actor_id: Uuid, prefijo: &str, limite: i64) -> Result<Vec<super::models::UsuarioBusqueda>, RepoError>;

    /// `GET /users/{email}/public-key` — como `buscar_por_email`, pero
    /// acotado a quién puede ver `actor_id` (2026-08-11). A propósito una
    /// función DISTINTA de `buscar_por_email` (usada por login/SSO/SCIM/
    /// passkeys/account-recovery, que nunca deben restringirse por
    /// visibilidad de grupo — ahí el caller busca SU PROPIA cuenta, no a
    /// otro usuario para compartir).
    async fn buscar_por_email_visible(&self, actor_id: Uuid, email: &str) -> Result<Option<User>, RepoError>;
}

/// F-24: mismo patrón que `DeviceChallengeRepository` — token de un solo
/// uso, hasheado, con TTL y `consumed_at`.
pub trait EmailVerificationRepository {
    async fn crear(&self, user_id: Uuid, code_hash: &[u8], expires_at: OffsetDateTime) -> Result<Uuid, RepoError>;

    async fn buscar_pendiente_por_usuario(&self, user_id: Uuid) -> Result<Option<EmailVerificationRow>, RepoError>;

    async fn consumir(&self, id: Uuid) -> Result<(), RepoError>;

    /// Invalida cualquier desafío pendiente de `user_id` — usado antes de
    /// emitir uno nuevo (reenvío), para que sólo el último código emitido
    /// sea válido.
    async fn invalidar_pendientes_de_usuario(&self, user_id: Uuid) -> Result<(), RepoError>;

    async fn marcar_verificado(&self, user_id: Uuid) -> Result<(), RepoError>;
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
    async fn crear(&self, nuevo: NuevoUsuario<'_>, ya_verificado: bool) -> Result<User, RepoError> {
        let mut tx = self.pool.begin().await?;
        // Bootstrap: si todavía no existe ningún usuario en toda la
        // instancia, el primer auto-registro (`POST /auth/register`) nace
        // como `admin` en vez de `user` — decisión explícita del usuario,
        // acepta el trade-off de que si F-24 (self-registration) está
        // habilitada públicamente, quien gane la carrera a ser el primer
        // registro de una instancia recién levantada se queda con admin.
        // Para cualquier registro posterior (ya existe al menos un usuario)
        // sigue naciendo `user` — promover a alguien más sigue siendo una
        // acción deliberada aparte (CLI `admin promote-to-admin`, F-41).
        // El `exists` corre dentro de la misma transacción que el insert,
        // no elimina la ventana de carrera bajo concurrencia real pero
        // alcanza para el caso que importa: nadie más registra en el mismo
        // instante en que se levanta una instancia nueva.
        // F-24: el mismo bootstrap nace también con `email_verified_at` ya
        // fijado (nadie más existe todavía para aprobar/enviar un código) —
        // sin importar `ya_verificado`. Para cualquier registro posterior,
        // `ya_verificado` es quien decide (`false` en auto-registro normal,
        // `true` en JIT de SSO, que el IdP ya vouched).
        let fila = sqlx::query!(
            r#"
            insert into users (email, display_name, role_id, email_verified_at)
            values ($1, $2,
                (select id from roles where name =
                    case when exists (select 1 from users) then 'user' else 'admin' end),
                case when (not exists (select 1 from users)) or $3 then now() else null end
            )
            returning id, security_stamp, created_at
            "#,
            nuevo.email,
            nuevo.display_name,
            ya_verificado,
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
               where email = $1 and active and deleted_at is null and email_verified_at is not null"#,
            email,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(fila.map(|f| User { id: f.id, security_stamp: f.security_stamp, created_at: f.created_at }))
    }

    async fn buscar_por_id(&self, user_id: Uuid) -> Result<Option<User>, RepoError> {
        let fila = sqlx::query!(
            r#"select id, security_stamp, created_at from users
               where id = $1 and active and deleted_at is null and email_verified_at is not null"#,
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
            r#"select email, display_name from users
               where id = $1 and active and deleted_at is null and email_verified_at is not null"#,
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
            where u.email = $1 and u.active and u.deleted_at is null and u.email_verified_at is not null
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

    async fn existe_alguno(&self) -> Result<bool, RepoError> {
        let fila = sqlx::query!(r#"select exists(select 1 from users) as "existe!""#).fetch_one(&self.pool).await?;
        Ok(fila.existe)
    }

    async fn buscar_no_verificado_por_email(&self, email: &str) -> Result<Option<User>, RepoError> {
        let fila = sqlx::query!(
            r#"select id, security_stamp, created_at from users
               where email = $1 and active and deleted_at is null and email_verified_at is null"#,
            email,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(fila.map(|f| User { id: f.id, security_stamp: f.security_stamp, created_at: f.created_at }))
    }

    async fn buscar_por_prefijo(
        &self,
        actor_id: Uuid,
        prefijo: &str,
        limite: i64,
    ) -> Result<Vec<super::models::UsuarioBusqueda>, RepoError> {
        let patron = format!("%{prefijo}%");
        let filas = sqlx::query!(
            r#"
            select u.id, u.email, u.display_name, uk.public_key_x25519,
                   (u.avatar_content_type is not null) as "has_avatar!"
            from users u
            join user_keys uk on uk.user_id = u.id
            where u.active and u.deleted_at is null and u.email_verified_at is not null
              and (u.email ilike $2 or u.display_name ilike $2)
              and (
                    u.id = $1
                    or exists (select 1 from users a join role_permissions rp on rp.role_id = a.role_id
                            where a.id = $1 and rp.permission = '*')
                    or exists (select 1 from group_members gm1 join group_members gm2 on gm1.group_id = gm2.group_id
                               where gm1.user_id = $1 and gm2.user_id = u.id)
                    or (
                        exists (select 1 from group_members gma where gma.user_id = $1 and gma.is_admin)
                        and (
                            exists (select 1 from group_members gmt where gmt.user_id = u.id and gmt.is_admin)
                            or exists (select 1 from users b join role_permissions rp2 on rp2.role_id = b.role_id
                                       where b.id = u.id and rp2.permission = '*')
                        )
                    )
                  )
            order by u.email
            limit $3
            "#,
            actor_id,
            patron,
            limite,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(filas
            .into_iter()
            .map(|f| super::models::UsuarioBusqueda {
                id: f.id,
                email: f.email,
                display_name: f.display_name,
                public_key_x25519: f.public_key_x25519,
                has_avatar: f.has_avatar,
            })
            .collect())
    }

    async fn buscar_por_email_visible(&self, actor_id: Uuid, email: &str) -> Result<Option<User>, RepoError> {
        let fila = sqlx::query!(
            r#"
            select u.id, u.security_stamp, u.created_at from users u
            where u.email = $2 and u.active and u.deleted_at is null and u.email_verified_at is not null
              and (
                    u.id = $1
                    or exists (select 1 from users a join role_permissions rp on rp.role_id = a.role_id
                            where a.id = $1 and rp.permission = '*')
                    or exists (select 1 from group_members gm1 join group_members gm2 on gm1.group_id = gm2.group_id
                               where gm1.user_id = $1 and gm2.user_id = u.id)
                    or (
                        exists (select 1 from group_members gma where gma.user_id = $1 and gma.is_admin)
                        and (
                            exists (select 1 from group_members gmt where gmt.user_id = u.id and gmt.is_admin)
                            or exists (select 1 from users b join role_permissions rp2 on rp2.role_id = b.role_id
                                       where b.id = u.id and rp2.permission = '*')
                        )
                    )
                  )
            "#,
            actor_id,
            email,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(fila.map(|f| User { id: f.id, security_stamp: f.security_stamp, created_at: f.created_at }))
    }
}

impl EmailVerificationRepository for PgUserRepository {
    async fn crear(&self, user_id: Uuid, code_hash: &[u8], expires_at: OffsetDateTime) -> Result<Uuid, RepoError> {
        let fila = sqlx::query!(
            r#"
            insert into email_verification_challenges (user_id, code_hash, expires_at)
            values ($1, $2, $3)
            returning id
            "#,
            user_id,
            code_hash,
            expires_at,
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(fila.id)
    }

    async fn buscar_pendiente_por_usuario(&self, user_id: Uuid) -> Result<Option<EmailVerificationRow>, RepoError> {
        let fila = sqlx::query!(
            r#"select id, user_id, code_hash from email_verification_challenges
               where user_id = $1 and consumed_at is null and expires_at > now()
               order by id desc limit 1"#,
            user_id,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(fila.map(|f| EmailVerificationRow { id: f.id, user_id: f.user_id, code_hash: f.code_hash }))
    }

    async fn consumir(&self, id: Uuid) -> Result<(), RepoError> {
        sqlx::query!(r#"update email_verification_challenges set consumed_at = now() where id = $1"#, id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn invalidar_pendientes_de_usuario(&self, user_id: Uuid) -> Result<(), RepoError> {
        sqlx::query!(
            r#"update email_verification_challenges set consumed_at = now()
               where user_id = $1 and consumed_at is null"#,
            user_id,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn marcar_verificado(&self, user_id: Uuid) -> Result<(), RepoError> {
        sqlx::query!(r#"update users set email_verified_at = now() where id = $1"#, user_id)
            .execute(&self.pool)
            .await?;
        Ok(())
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
              and u.active and u.deleted_at is null and u.email_verified_at is not null
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
              and u.active and u.deleted_at is null and u.email_verified_at is not null
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
