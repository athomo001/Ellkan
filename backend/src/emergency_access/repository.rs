// Autor: Athan Espinoza

#![allow(async_fn_in_trait)]

use uuid::Uuid;

use crate::error::RepoError;

use super::models::{EmergencyAccess, EmergencyAccessRequest};

pub trait EmergencyAccessPolicyRepository {
    async fn habilitado(&self) -> Result<bool, RepoError>;
    async fn actualizar(&self, habilitado: bool) -> Result<(), RepoError>;
}

pub trait EmergencyAccessRepository {
    #[allow(clippy::too_many_arguments)]
    async fn crear(
        &self,
        granter_id: Uuid,
        grantee_id: Uuid,
        access_level: &str,
        sealed_material: &[u8],
        wait_time_days: i32,
    ) -> Result<EmergencyAccess, RepoError>;

    async fn buscar(&self, id: Uuid) -> Result<Option<EmergencyAccess>, RepoError>;

    async fn listar_por_titular_o_contacto(&self, user_id: Uuid) -> Result<Vec<EmergencyAccess>, RepoError>;

    async fn marcar_status(&self, id: Uuid, status: &str) -> Result<(), RepoError>;

    async fn eliminar(&self, id: Uuid) -> Result<(), RepoError>;
}

pub trait EmergencyAccessRequestRepository {
    async fn crear(&self, emergency_access_id: Uuid) -> Result<EmergencyAccessRequest, RepoError>;

    async fn pendiente_de(&self, emergency_access_id: Uuid) -> Result<Option<EmergencyAccessRequest>, RepoError>;

    /// `true` si había una pendiente y se resolvió — usado tanto por
    /// aprobar/rechazar (titular) como por el job de timeout.
    async fn resolver(&self, id: Uuid, status: &str) -> Result<bool, RepoError>;

    /// Fila más reciente (cualquier estado) — para saber si el `grantee` ya
    /// tiene acceso vigente al listar (`GET /me/emergency-access`).
    async fn ultima_de(&self, emergency_access_id: Uuid) -> Result<Option<EmergencyAccessRequest>, RepoError>;

    /// Solicitudes pendientes cuyo plazo (`requested_at + wait_time_days`)
    /// ya venció — consumido por el job programado (F-36).
    async fn listar_vencidas(&self) -> Result<Vec<(EmergencyAccessRequest, Uuid)>, RepoError>;
}

#[derive(Clone)]
pub struct PgEmergencyAccessPolicyRepository {
    pub pool: sqlx::PgPool,
}

impl EmergencyAccessPolicyRepository for PgEmergencyAccessPolicyRepository {
    async fn habilitado(&self) -> Result<bool, RepoError> {
        let fila = sqlx::query!(r#"select emergency_access_enabled from organizations where id = 1"#)
            .fetch_one(&self.pool)
            .await?;
        Ok(fila.emergency_access_enabled)
    }

    async fn actualizar(&self, habilitado: bool) -> Result<(), RepoError> {
        sqlx::query!(r#"update organizations set emergency_access_enabled = $1 where id = 1"#, habilitado)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct PgEmergencyAccessRepository {
    pub pool: sqlx::PgPool,
}

#[allow(clippy::too_many_arguments)]
fn fila_a_ea(
    id: Uuid,
    granter_id: Uuid,
    grantee_id: Uuid,
    access_level: String,
    sealed_material: Vec<u8>,
    wait_time_days: i32,
    status: String,
    created_at: time::OffsetDateTime,
) -> EmergencyAccess {
    EmergencyAccess { id, granter_id, grantee_id, access_level, sealed_material, wait_time_days, status, created_at }
}

impl EmergencyAccessRepository for PgEmergencyAccessRepository {
    async fn crear(
        &self,
        granter_id: Uuid,
        grantee_id: Uuid,
        access_level: &str,
        sealed_material: &[u8],
        wait_time_days: i32,
    ) -> Result<EmergencyAccess, RepoError> {
        let fila = sqlx::query!(
            r#"
            insert into emergency_access (granter_id, grantee_id, access_level, sealed_material, wait_time_days)
            values ($1, $2, $3, $4, $5)
            returning id, granter_id, grantee_id, access_level, sealed_material, wait_time_days, status, created_at
            "#,
            granter_id,
            grantee_id,
            access_level,
            sealed_material,
            wait_time_days,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(fila_a_ea(
            fila.id,
            fila.granter_id,
            fila.grantee_id,
            fila.access_level,
            fila.sealed_material,
            fila.wait_time_days,
            fila.status,
            fila.created_at,
        ))
    }

    async fn buscar(&self, id: Uuid) -> Result<Option<EmergencyAccess>, RepoError> {
        let fila = sqlx::query!(
            r#"select id, granter_id, grantee_id, access_level, sealed_material, wait_time_days, status, created_at
               from emergency_access where id = $1"#,
            id,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(fila.map(|f| {
            fila_a_ea(
                f.id,
                f.granter_id,
                f.grantee_id,
                f.access_level,
                f.sealed_material,
                f.wait_time_days,
                f.status,
                f.created_at,
            )
        }))
    }

    async fn listar_por_titular_o_contacto(&self, user_id: Uuid) -> Result<Vec<EmergencyAccess>, RepoError> {
        let filas = sqlx::query!(
            r#"select id, granter_id, grantee_id, access_level, sealed_material, wait_time_days, status, created_at
               from emergency_access where granter_id = $1 or grantee_id = $1 order by created_at"#,
            user_id,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(filas
            .into_iter()
            .map(|f| {
                fila_a_ea(
                    f.id,
                    f.granter_id,
                    f.grantee_id,
                    f.access_level,
                    f.sealed_material,
                    f.wait_time_days,
                    f.status,
                    f.created_at,
                )
            })
            .collect())
    }

    async fn marcar_status(&self, id: Uuid, status: &str) -> Result<(), RepoError> {
        sqlx::query!(r#"update emergency_access set status = $2 where id = $1"#, id, status)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn eliminar(&self, id: Uuid) -> Result<(), RepoError> {
        sqlx::query!(r#"delete from emergency_access_requests where emergency_access_id = $1"#, id)
            .execute(&self.pool)
            .await?;
        sqlx::query!(r#"delete from emergency_access where id = $1"#, id).execute(&self.pool).await?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct PgEmergencyAccessRequestRepository {
    pub pool: sqlx::PgPool,
}

impl EmergencyAccessRequestRepository for PgEmergencyAccessRequestRepository {
    async fn crear(&self, emergency_access_id: Uuid) -> Result<EmergencyAccessRequest, RepoError> {
        let fila = sqlx::query!(
            r#"
            insert into emergency_access_requests (emergency_access_id)
            values ($1)
            returning id, emergency_access_id, requested_at, status, resolved_at
            "#,
            emergency_access_id,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => RepoError::Conflict,
            _ => RepoError::Database(e),
        })?;

        Ok(EmergencyAccessRequest {
            id: fila.id,
            emergency_access_id: fila.emergency_access_id,
            requested_at: fila.requested_at,
            status: fila.status,
            resolved_at: fila.resolved_at,
        })
    }

    async fn pendiente_de(&self, emergency_access_id: Uuid) -> Result<Option<EmergencyAccessRequest>, RepoError> {
        let fila = sqlx::query!(
            r#"select id, emergency_access_id, requested_at, status, resolved_at
               from emergency_access_requests where emergency_access_id = $1 and status = 'pending'"#,
            emergency_access_id,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(fila.map(|f| EmergencyAccessRequest {
            id: f.id,
            emergency_access_id: f.emergency_access_id,
            requested_at: f.requested_at,
            status: f.status,
            resolved_at: f.resolved_at,
        }))
    }

    async fn resolver(&self, id: Uuid, status: &str) -> Result<bool, RepoError> {
        let resultado = sqlx::query!(
            r#"update emergency_access_requests set status = $2, resolved_at = now()
               where id = $1 and status = 'pending'"#,
            id,
            status,
        )
        .execute(&self.pool)
        .await?;
        Ok(resultado.rows_affected() == 1)
    }

    async fn ultima_de(&self, emergency_access_id: Uuid) -> Result<Option<EmergencyAccessRequest>, RepoError> {
        let fila = sqlx::query!(
            r#"select id, emergency_access_id, requested_at, status, resolved_at
               from emergency_access_requests where emergency_access_id = $1
               order by requested_at desc limit 1"#,
            emergency_access_id,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(fila.map(|f| EmergencyAccessRequest {
            id: f.id,
            emergency_access_id: f.emergency_access_id,
            requested_at: f.requested_at,
            status: f.status,
            resolved_at: f.resolved_at,
        }))
    }

    async fn listar_vencidas(&self) -> Result<Vec<(EmergencyAccessRequest, Uuid)>, RepoError> {
        let filas = sqlx::query!(
            r#"
            select r.id, r.emergency_access_id, r.requested_at, r.status, r.resolved_at, e.granter_id
            from emergency_access_requests r
            join emergency_access e on e.id = r.emergency_access_id
            where r.status = 'pending'
              and r.requested_at + (e.wait_time_days || ' days')::interval <= now()
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(filas
            .into_iter()
            .map(|f| {
                (
                    EmergencyAccessRequest {
                        id: f.id,
                        emergency_access_id: f.emergency_access_id,
                        requested_at: f.requested_at,
                        status: f.status,
                        resolved_at: f.resolved_at,
                    },
                    f.granter_id,
                )
            })
            .collect())
    }
}
