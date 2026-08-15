// Autor: Athan Espinoza

#![allow(async_fn_in_trait)]

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use uuid::Uuid;

use crate::error::RepoError;

use super::models::{ExportPolicy, FilaExportGrupo, FilaExportUsuario, MiembroDeGrupoExport};

pub trait ExportPolicyRepository {
    async fn obtener(&self) -> Result<ExportPolicy, RepoError>;
    async fn actualizar(&self, policy: &ExportPolicy) -> Result<(), RepoError>;
}

/// F-29: proyección de lectura pura sobre `users`/`group_members`/`groups`/
/// `passkeys`(sólo conteo)/`user_totp_credentials` — sin tabla propia, ver
/// `spec/02-modelo-de-datos.md` §5bis.
pub trait ExportRepository {
    async fn listar_usuarios(&self) -> Result<Vec<FilaExportUsuario>, RepoError>;
    async fn listar_grupos(&self) -> Result<Vec<FilaExportGrupo>, RepoError>;
}

#[derive(Clone)]
pub struct PgExportPolicyRepository {
    pub pool: sqlx::PgPool,
}

impl ExportPolicyRepository for PgExportPolicyRepository {
    async fn obtener(&self) -> Result<ExportPolicy, RepoError> {
        let fila = sqlx::query!(
            r#"select export_enabled, allowed_formats, import_enabled from export_policy where organization_id = 1"#,
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(ExportPolicy {
            export_enabled: fila.export_enabled,
            allowed_formats: fila.allowed_formats,
            import_enabled: fila.import_enabled,
        })
    }

    async fn actualizar(&self, policy: &ExportPolicy) -> Result<(), RepoError> {
        sqlx::query!(
            r#"update export_policy set export_enabled = $1, allowed_formats = $2, import_enabled = $3
               where organization_id = 1"#,
            policy.export_enabled,
            &policy.allowed_formats,
            policy.import_enabled,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct PgExportRepository {
    pub pool: sqlx::PgPool,
}

impl ExportRepository for PgExportRepository {
    async fn listar_usuarios(&self) -> Result<Vec<FilaExportUsuario>, RepoError> {
        let filas = sqlx::query!(
            r#"
            select
                u.id, u.email, u.display_name, r.name as role, u.active, u.deleted_at,
                u.created_at, u.updated_at,
                exists(
                    select 1 from user_totp_credentials t
                    where t.user_id = u.id and t.confirmed_at is not null
                ) as "mfa_configured!",
                (select count(*) from passkeys p where p.user_id = u.id) as "passkey_count!",
                uk.public_key_x25519 as "public_key_x25519?"
            from users u
            join roles r on r.id = u.role_id
            left join user_keys uk on uk.user_id = u.id
            order by u.email
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let membresias = sqlx::query!(
            r#"select gm.user_id, g.name from group_members gm join groups g on g.id = gm.group_id order by g.name"#,
        )
        .fetch_all(&self.pool)
        .await?;
        let mut grupos_por_usuario: HashMap<Uuid, Vec<String>> = HashMap::new();
        for fila in membresias {
            grupos_por_usuario.entry(fila.user_id).or_default().push(fila.name);
        }

        Ok(filas
            .into_iter()
            .map(|fila| FilaExportUsuario {
                groups: grupos_por_usuario.remove(&fila.id).unwrap_or_default(),
                id: fila.id,
                email: fila.email,
                display_name: fila.display_name,
                role: fila.role,
                active: fila.active,
                deleted_at: fila.deleted_at,
                created_at: fila.created_at,
                updated_at: fila.updated_at,
                mfa_configured: fila.mfa_configured,
                passkey_count: fila.passkey_count,
                public_key_x25519_b64: fila.public_key_x25519.map(|b| B64.encode(b)),
            })
            .collect())
    }

    async fn listar_grupos(&self) -> Result<Vec<FilaExportGrupo>, RepoError> {
        let filas = sqlx::query!(
            r#"select id, name, parent_group_id, deleted_at from groups order by name"#,
        )
        .fetch_all(&self.pool)
        .await?;

        let miembros = sqlx::query!(r#"select group_id, user_id, is_admin from group_members"#)
            .fetch_all(&self.pool)
            .await?;
        let mut miembros_por_grupo: HashMap<Uuid, Vec<MiembroDeGrupoExport>> = HashMap::new();
        for fila in miembros {
            miembros_por_grupo
                .entry(fila.group_id)
                .or_default()
                .push(MiembroDeGrupoExport { user_id: fila.user_id, is_admin: fila.is_admin });
        }

        Ok(filas
            .into_iter()
            .map(|fila| FilaExportGrupo {
                members: miembros_por_grupo.remove(&fila.id).unwrap_or_default(),
                id: fila.id,
                name: fila.name,
                parent_group_id: fila.parent_group_id,
                deleted_at: fila.deleted_at,
            })
            .collect())
    }
}
