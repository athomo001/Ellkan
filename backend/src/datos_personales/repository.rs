// Autor: Athan Espinoza

//! Lecturas para la exportación de datos personales. Todo filtrado por el
//! `user_id` de la sesión: nadie exporta datos de otra cuenta.

#![allow(async_fn_in_trait)]

use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::RepoError;

use super::models::{
    ContactoEmergencia, Cuenta, DatosPersonales, Dispositivo, EntradaAuditoria, Grupo, IdentidadSso, MAX_AUDITORIA, Passkey, Sesion,
};

const NO_INCLUIDO: &str = "El contenido de la bóveda (contraseñas, notas, nombres, usuarios, URLs y carpetas) está cifrado de extremo a extremo y el servidor no puede leerlo: se exporta desde la aplicación (CSV o KeePass). Tampoco se incluyen claves ni secretos criptográficos, ni el detalle de cada entrada de auditoría, que puede nombrar a otras personas.";

pub trait DatosPersonalesRepository {
    /// `None` si la cuenta no existe o está borrada.
    async fn leer(&self, user_id: Uuid) -> Result<Option<DatosPersonales>, RepoError>;
}

#[derive(Clone)]
pub struct PgDatosPersonalesRepository {
    pub pool: sqlx::PgPool,
}

impl DatosPersonalesRepository for PgDatosPersonalesRepository {
    async fn leer(&self, user_id: Uuid) -> Result<Option<DatosPersonales>, RepoError> {
        leer(&self.pool, user_id).await
    }
}

async fn leer(pool: &sqlx::PgPool, user_id: Uuid) -> Result<Option<DatosPersonales>, RepoError> {
    let Some(account) = sqlx::query_as!(
        Cuenta,
        r#"select u.id, u.email, u.display_name, r.name as "role?", u.active, u.external_id, u.locale, u.theme,
                  u.avatar_bytes is not null as "has_avatar!", u.email_verified_at, u.created_at, u.updated_at
           from users u left join roles r on r.id = u.role_id
           where u.id = $1 and u.deleted_at is null"#,
        user_id
    )
    .fetch_optional(pool)
    .await?
    else {
        return Ok(None);
    };

    let groups = sqlx::query_as!(
        Grupo,
        r#"select g.name, gm.is_admin, gm.created_at as joined_at
           from group_members gm join groups g on g.id = gm.group_id
           where gm.user_id = $1 and g.deleted_at is null
           order by g.name"#,
        user_id
    )
    .fetch_all(pool)
    .await?;

    let sessions = sqlx::query_as!(
        Sesion,
        r#"select dispositivo as device, created_at, last_used_at, expires_at, revoked_at
           from sessions where user_id = $1 order by created_at desc"#,
        user_id
    )
    .fetch_all(pool)
    .await?;

    let known_devices = sqlx::query_as!(
        Dispositivo,
        r#"select label, first_seen_at, last_seen_at from known_devices where user_id = $1 order by first_seen_at"#,
        user_id
    )
    .fetch_all(pool)
    .await?;

    let passkeys = sqlx::query_as!(
        Passkey,
        r#"select label, created_at, last_used_at from passkeys where user_id = $1 order by created_at"#,
        user_id
    )
    .fetch_all(pool)
    .await?;

    let totp_enabled = sqlx::query_scalar!(
        r#"select exists(select 1 from user_totp_credentials
                         where user_id = $1 and confirmed_at is not null and deleted_at is null) as "existe!""#,
        user_id
    )
    .fetch_one(pool)
    .await?;

    let sso_identities = sqlx::query_as!(
        IdentidadSso,
        r#"select provider, created_at from sso_identities where user_id = $1 order by created_at"#,
        user_id
    )
    .fetch_all(pool)
    .await?;

    let emergency_access = sqlx::query_as!(
        ContactoEmergencia,
        r#"select case when ea.granter_id = $1 then 'granter' else 'grantee' end as "role!",
                  u.email as other_email, ea.status, ea.wait_time_days, ea.created_at
           from emergency_access ea
           join users u on u.id = case when ea.granter_id = $1 then ea.grantee_id else ea.granter_id end
           where ea.granter_id = $1 or ea.grantee_id = $1
           order by ea.created_at"#,
        user_id
    )
    .fetch_all(pool)
    .await?;

    let mut audit_entries = sqlx::query_as!(
        EntradaAuditoria,
        r#"select event_type, subject_type, created_at from audit_log_entries
           where actor_user_id = $1 order by id desc limit $2"#,
        user_id,
        MAX_AUDITORIA + 1
    )
    .fetch_all(pool)
    .await?;
    let audit_entries_truncated = audit_entries.len() as i64 > MAX_AUDITORIA;
    audit_entries.truncate(MAX_AUDITORIA as usize);

    Ok(Some(DatosPersonales {
        generated_at: OffsetDateTime::now_utc(),
        account,
        groups,
        sessions,
        known_devices,
        passkeys,
        totp_enabled,
        sso_identities,
        emergency_access,
        audit_entries,
        audit_entries_truncated,
        not_included: NO_INCLUIDO,
    }))
}
