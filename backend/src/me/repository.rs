// Autor: Athan Espinoza

#![allow(async_fn_in_trait)]

use uuid::Uuid;

use crate::error::RepoError;

use super::models::{Avatar, NuevaClavePrivada, Perfil, Preferencias};

pub trait PreferenciasRepository {
    async fn obtener(&self, user_id: Uuid) -> Result<Preferencias, RepoError>;
    async fn actualizar(&self, user_id: Uuid, p: &Preferencias) -> Result<(), RepoError>;
}

pub trait PerfilRepository {
    async fn obtener(&self, user_id: Uuid) -> Result<Perfil, RepoError>;

    /// Pendiente #133: guarda el primer par de claves de una cuenta que no
    /// tiene (alta por SSO/SCIM/directorio: sin fila en `user_keys`, ELK-01).
    /// `false` si ya tenía: nunca pisa claves existentes (eso es cambiar la
    /// contraseña, con prueba de posesión).
    async fn enrolar_claves(&self, user_id: Uuid, claves: &super::models::ClavesIniciales) -> Result<bool, RepoError>;

    /// ELK-01 (#147, a2): si `session_id` es de `user_id`, la emitió el
    /// callback SSO y tiene menos de `minutos`. Es la prueba independiente del
    /// login por firma que exige el enrolamiento.
    async fn sesion_sso_reciente(&self, session_id: Uuid, user_id: Uuid, minutos: i32) -> Result<bool, RepoError>;
}

pub trait AvatarRepository {
    async fn obtener(&self, user_id: Uuid) -> Result<Option<Avatar>, RepoError>;
    async fn actualizar(&self, user_id: Uuid, avatar: &Avatar) -> Result<(), RepoError>;
    async fn eliminar(&self, user_id: Uuid) -> Result<(), RepoError>;
}

pub trait ClavePrivadaRepository {
    /// Reemplaza el blob cifrado y rota `security_stamp` en la misma
    /// transacción — invalida toda sesión activa (incluida la que hace este
    /// mismo cambio), mismo idioma exacto que `users_admin::repository`/
    /// `scim::repository` para "desactivar invalida sesiones ya abiertas".
    async fn actualizar(&self, user_id: Uuid, nueva: &NuevaClavePrivada) -> Result<(), RepoError>;
    /// QA-03: reemplaza el blob sólo si la cuenta todavía no tiene
    /// verificador (`auth_verifier is null`), sin rotar `security_stamp`.
    /// `false` si no había nada que mejorar.
    async fn mejorar_sello_legado(&self, user_id: Uuid, nueva: &NuevaClavePrivada) -> Result<bool, RepoError>;
}

#[derive(Clone)]
pub struct PgPreferenciasRepository {
    pub pool: sqlx::PgPool,
}

impl PreferenciasRepository for PgPreferenciasRepository {
    async fn obtener(&self, user_id: Uuid) -> Result<Preferencias, RepoError> {
        let fila = sqlx::query!(
            r#"select locale, theme, clipboard_clear_minutes, auto_lock_minutes
               from users where id = $1"#,
            user_id,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(Preferencias {
            locale: fila.locale,
            theme: fila.theme,
            clipboard_clear_minutes: fila.clipboard_clear_minutes,
            auto_lock_minutes: fila.auto_lock_minutes,
        })
    }

    async fn actualizar(&self, user_id: Uuid, p: &Preferencias) -> Result<(), RepoError> {
        sqlx::query!(
            r#"update users set locale = $1, theme = $2, clipboard_clear_minutes = $3, auto_lock_minutes = $4
               where id = $5"#,
            p.locale,
            p.theme,
            p.clipboard_clear_minutes,
            p.auto_lock_minutes,
            user_id,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

impl PerfilRepository for PgPreferenciasRepository {
    async fn enrolar_claves(&self, user_id: Uuid, claves: &super::models::ClavesIniciales) -> Result<bool, RepoError> {
        // ELK-01 (#147): la cuenta sin enrolar no tiene fila; si ya la tiene,
        // `on conflict do nothing` no toca nada y se devuelve `false`.
        let resultado = sqlx::query!(
            r#"insert into user_keys (
                   user_id, public_key_x25519, public_key_ed25519, encrypted_private_key_blob,
                   private_key_nonce, kdf_salt, kdf_params, auth_verifier
               )
               values ($1, $2, $3, $4, $5, $6, $7, $8)
               on conflict (user_id) do nothing"#,
            user_id,
            claves.public_key_x25519,
            claves.public_key_ed25519,
            claves.encrypted_private_key_blob,
            claves.private_key_nonce,
            claves.kdf_salt,
            sqlx::types::Json(claves.kdf_params) as _,
            claves.auth_verifier(),
        )
        .execute(&self.pool)
        .await?;
        Ok(resultado.rows_affected() == 1)
    }

    async fn sesion_sso_reciente(&self, session_id: Uuid, user_id: Uuid, minutos: i32) -> Result<bool, RepoError> {
        let fila = sqlx::query!(
            r#"select exists (
                   select 1 from sessions
                   where id = $1 and user_id = $2 and emitida_por_sso and revoked_at is null
                     and created_at > now() - make_interval(mins => $3)
               ) as "ok!""#,
            session_id,
            user_id,
            minutos,
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(fila.ok)
    }

    async fn obtener(&self, user_id: Uuid) -> Result<Perfil, RepoError> {
        let fila = sqlx::query!(
            r#"select u.email, u.display_name, r.name as role, u.created_at, u.updated_at,
                      coalesce(uk.created_at, u.created_at) as "keys_created_at!",
                      (uk.user_id is null) as "necesita_enrolar_claves!"
               from users u
               join roles r on r.id = u.role_id
               left join user_keys uk on uk.user_id = u.id
               where u.id = $1"#,
            user_id,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(Perfil {
            email: fila.email,
            display_name: fila.display_name,
            role: fila.role,
            created_at: fila.created_at,
            updated_at: fila.updated_at,
            keys_created_at: fila.keys_created_at,
            necesita_enrolar_claves: fila.necesita_enrolar_claves,
        })
    }
}

impl AvatarRepository for PgPreferenciasRepository {
    async fn obtener(&self, user_id: Uuid) -> Result<Option<Avatar>, RepoError> {
        let fila = sqlx::query!(r#"select avatar_bytes, avatar_content_type from users where id = $1"#, user_id)
            .fetch_one(&self.pool)
            .await?;

        Ok(match (fila.avatar_bytes, fila.avatar_content_type) {
            (Some(bytes), Some(content_type)) => Some(Avatar { bytes, content_type }),
            _ => None,
        })
    }

    async fn actualizar(&self, user_id: Uuid, avatar: &Avatar) -> Result<(), RepoError> {
        sqlx::query!(
            r#"update users set avatar_bytes = $1, avatar_content_type = $2 where id = $3"#,
            avatar.bytes,
            avatar.content_type,
            user_id,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn eliminar(&self, user_id: Uuid) -> Result<(), RepoError> {
        sqlx::query!(r#"update users set avatar_bytes = null, avatar_content_type = null where id = $1"#, user_id,)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

impl ClavePrivadaRepository for PgPreferenciasRepository {
    async fn actualizar(&self, user_id: Uuid, nueva: &NuevaClavePrivada) -> Result<(), RepoError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query!(
            r#"update user_keys set encrypted_private_key_blob = $1, private_key_nonce = $2,
               kdf_salt = $3, kdf_params = $5, auth_verifier = $6, updated_at = now() where user_id = $4"#,
            nueva.encrypted_private_key_blob,
            nueva.private_key_nonce,
            nueva.kdf_salt,
            user_id,
            sqlx::types::Json(nueva.kdf_params) as _,
            nueva.auth_verifier(),
        )
        .execute(&mut *tx)
        .await?;
        // `must_change_passphrase = false` en el mismo UPDATE: si esta
        // llamada viene de una sesión `RequiereCambiarPassphrase` (passphrase
        // provisoria), cambiar la passphrase ya cierra ese requisito — sin
        // esto, el próximo login volvería a exigirlo con la passphrase nueva.
        sqlx::query!(
            r#"update users set security_stamp = gen_random_uuid(), must_change_passphrase = false where id = $1"#,
            user_id,
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn mejorar_sello_legado(&self, user_id: Uuid, nueva: &NuevaClavePrivada) -> Result<bool, RepoError> {
        let resultado = sqlx::query!(
            r#"update user_keys set encrypted_private_key_blob = $1, private_key_nonce = $2,
               kdf_salt = $3, kdf_params = $5, auth_verifier = $6, updated_at = now()
               where user_id = $4 and auth_verifier is null"#,
            nueva.encrypted_private_key_blob,
            nueva.private_key_nonce,
            nueva.kdf_salt,
            user_id,
            sqlx::types::Json(nueva.kdf_params) as _,
            nueva.auth_verifier(),
        )
        .execute(&self.pool)
        .await?;
        Ok(resultado.rows_affected() == 1)
    }
}
