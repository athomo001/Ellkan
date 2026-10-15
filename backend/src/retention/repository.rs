// Autor: Athan Espinoza

#![allow(async_fn_in_trait)]

use crate::error::RepoError;

use super::models::{ResultadoPurga, RetentionPolicy};

pub trait RetentionPolicyRepository {
    async fn obtener(&self) -> Result<RetentionPolicy, RepoError>;
    async fn actualizar(&self, policy: &RetentionPolicy) -> Result<(), RepoError>;
}

/// Hard-delete físico de filas soft-deleted más viejas que la política —
/// `audit_log_entries` nunca pasa por acá (F-40: excluido explícitamente,
/// retención propia vía `audit_log_retention_days`). Alcance documentado: no
/// purga `users` (tiene su propio flujo dedicado con dry-run + transferencia,
/// checkbox aparte de F-40) ni `metadata_keys`/`resource_types` (nada hoy
/// pone `deleted_at` en esas dos, y `resource_types` es catálogo de sistema,
/// no dato de usuario).
pub trait PurgeRepository {
    async fn purgar(&self, data_retention_days: i32, audit_log_retention_days: i32) -> Result<ResultadoPurga, RepoError>;
}

#[derive(Clone)]
pub struct PgRetentionPolicyRepository {
    pub pool: sqlx::PgPool,
}

impl RetentionPolicyRepository for PgRetentionPolicyRepository {
    async fn obtener(&self) -> Result<RetentionPolicy, RepoError> {
        let fila = sqlx::query!(
            r#"select data_retention_days, audit_log_retention_days from organizations where id = 1"#,
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(RetentionPolicy {
            data_retention_days: fila.data_retention_days,
            audit_log_retention_days: fila.audit_log_retention_days,
        })
    }

    async fn actualizar(&self, policy: &RetentionPolicy) -> Result<(), RepoError> {
        sqlx::query!(
            r#"update organizations set data_retention_days = $1, audit_log_retention_days = $2 where id = 1"#,
            policy.data_retention_days,
            policy.audit_log_retention_days,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct PgPurgeRepository {
    pub pool: sqlx::PgPool,
}

impl PurgeRepository for PgPurgeRepository {
    async fn purgar(&self, data_retention_days: i32, audit_log_retention_days: i32) -> Result<ResultadoPurga, RepoError> {
        let mut tx = self.pool.begin().await?;
        let mut resultado = ResultadoPurga::default();

        // Orden de borrado: dependientes antes que el padre, para no chocar
        // con las FK (`NO ACTION`, no `CASCADE`, a propósito — un hard-delete
        // que se olvida un dependiente falla ruidoso en vez de arrastrar
        // filas por accidente).
        sqlx::query!(
            r#"
            delete from resource_tags where resource_id in (
                select id from resources where deleted_at < now() - make_interval(days => $1)
            )
            "#,
            data_retention_days,
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query!(
            r#"
            delete from secret_envelopes where resource_id in (
                select id from resources where deleted_at < now() - make_interval(days => $1)
            )
            "#,
            data_retention_days,
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query!(
            r#"
            delete from folder_items where resource_id in (
                select id from resources where deleted_at < now() - make_interval(days => $1)
            )
            "#,
            data_retention_days,
        )
        .execute(&mut *tx)
        .await?;
        let r = sqlx::query!(
            r#"delete from resources where deleted_at < now() - make_interval(days => $1)"#,
            data_retention_days,
        )
        .execute(&mut *tx)
        .await?;
        resultado.resources = r.rows_affected();

        sqlx::query!(
            r#"
            delete from folder_items where folder_id in (
                select id from folders where deleted_at < now() - make_interval(days => $1)
            ) or child_folder_id in (
                select id from folders where deleted_at < now() - make_interval(days => $1)
            )
            "#,
            data_retention_days,
        )
        .execute(&mut *tx)
        .await?;
        let r = sqlx::query!(
            r#"delete from folders where deleted_at < now() - make_interval(days => $1)"#,
            data_retention_days,
        )
        .execute(&mut *tx)
        .await?;
        resultado.folders = r.rows_affected();

        sqlx::query!(
            r#"
            delete from resource_tags where tag_id in (
                select id from tags where deleted_at < now() - make_interval(days => $1)
            )
            "#,
            data_retention_days,
        )
        .execute(&mut *tx)
        .await?;
        let r = sqlx::query!(
            r#"delete from tags where deleted_at < now() - make_interval(days => $1)"#,
            data_retention_days,
        )
        .execute(&mut *tx)
        .await?;
        resultado.tags = r.rows_affected();

        sqlx::query!(
            r#"
            delete from group_members where group_id in (
                select id from groups where deleted_at < now() - make_interval(days => $1)
            )
            "#,
            data_retention_days,
        )
        .execute(&mut *tx)
        .await?;
        let r = sqlx::query!(
            r#"delete from groups where deleted_at < now() - make_interval(days => $1)"#,
            data_retention_days,
        )
        .execute(&mut *tx)
        .await?;
        resultado.groups = r.rows_affected();

        let r = sqlx::query!(
            r#"delete from user_totp_credentials where deleted_at < now() - make_interval(days => $1)"#,
            data_retention_days,
        )
        .execute(&mut *tx)
        .await?;
        resultado.user_totp_credentials = r.rows_affected();

        // Retención propia, independiente — F-40, nunca por `data_retention_days`.
        let r = sqlx::query!(
            r#"delete from audit_log_entries where created_at < now() - make_interval(days => $1)"#,
            audit_log_retention_days,
        )
        .execute(&mut *tx)
        .await?;
        resultado.audit_log_entries = r.rows_affected();

        // Minimización de datos (spec/14 punto 6.11): lo efímero de la
        // autenticación no sirve de nada una vez vencido o usado, y antes no
        // lo borraba nadie (crecía para siempre). Plazos fijos, no
        // configurables: un día de gracia para lo vencido (por si un reloj
        // está corrido) y una semana para los correos ya enviados o fallidos
        // (destinatario + cuerpo con códigos de verificación), que sólo sirven
        // para diagnosticar un envío. Los pendientes no se tocan. Orden: los
        // pedidos de aprobación de dispositivo antes que las sesiones que
        // referencian.
        let mut efimeros = 0;
        for sentencia in [
            "delete from device_approval_requests where expires_at < now() - interval '1 day'",
            "delete from sessions s where (s.expires_at < now() - interval '1 day' or s.revoked_at < now() - interval '1 day')
               and not exists (select 1 from device_approval_requests d where d.session_id = s.id)",
            "delete from auth_challenges where expires_at < now() - interval '1 day'",
            "delete from device_challenges where expires_at < now() - interval '1 day'",
            "delete from mfa_challenges where expires_at < now() - interval '1 day'",
            "delete from email_verification_challenges where expires_at < now() - interval '1 day'",
            "delete from recovery_reset_tokens where expires_at < now() - interval '1 day'",
            "delete from outbound_emails where status <> 'pendiente' and created_at < now() - interval '7 days'",
        ] {
            efimeros += sqlx::query(sentencia).execute(&mut *tx).await?.rows_affected();
        }
        resultado.datos_efimeros = efimeros;

        // Revocación remota: la clave pública de una cuenta purgada se guarda
        // sólo mientras haga falta avisarle a una app que estaba sin red —
        // misma retención que el log de auditoría (docs/revocacion-remota.md).
        sqlx::query("delete from cuentas_revocadas where revocada_en < now() - make_interval(days => $1)")
            .bind(audit_log_retention_days)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(resultado)
    }
}
