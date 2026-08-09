// Autor: Athan Espinoza

#![allow(async_fn_in_trait)]

use std::future::Future;

use uuid::Uuid;

use crate::error::RepoError;

use super::models::{AuditLogEntry, EventoAuditoria, FiltroAuditLog};

/// Techo duro de una página de `GET /admin/audit-log` — evita que un
/// `?limit=` desmedido tumbe el pool de conexiones con una sola query.
pub const LIMITE_PAGINA_MAXIMO: i64 = 200;
pub const LIMITE_PAGINA_DEFAULT: i64 = 50;

/// Techo de una exportación en una sola respuesta — por ahora sin streaming
/// real (llega si un operador concreto lo necesita); un operador con más
/// de 50k eventos en el rango pedido pagina el export por fecha.
pub const LIMITE_EXPORT_MAXIMO: i64 = 50_000;

pub trait AuditLogRepository {
    /// El consumidor de `DomainEvent::Auditoria` es el único llamador real —
    /// corre en su propia tarea `tokio`, nunca dentro de la transacción de
    /// la acción auditada (F-13). El future es `Send` explícito por el mismo
    /// motivo que `OutboundEmailRepository`.
    fn insertar(&self, evento: EventoAuditoria) -> impl Future<Output = Result<(), RepoError>> + Send;

    /// Keyset pagination por `id desc` (uuidv7 ya es monótono con
    /// `created_at`, no hace falta un cursor compuesto). `cursor` es el
    /// último `id` visto por el caller; `None` trae la página más reciente.
    fn listar(
        &self,
        filtro: &FiltroAuditLog,
        cursor: Option<Uuid>,
        limite: i64,
    ) -> impl Future<Output = Result<Vec<AuditLogEntry>, RepoError>> + Send;

    /// Orden cronológico ascendente (a diferencia de `listar`) — lo que un
    /// colector externo espera al ingerir incrementalmente.
    fn listar_para_exportar(
        &self,
        filtro: &FiltroAuditLog,
    ) -> impl Future<Output = Result<Vec<AuditLogEntry>, RepoError>> + Send;
}

#[derive(Clone)]
pub struct PgAuditLogRepository {
    pub pool: sqlx::PgPool,
}

struct FilaAuditLog {
    id: Uuid,
    actor_user_id: Option<Uuid>,
    actor_email: Option<String>,
    event_type: String,
    subject_type: Option<String>,
    subject_id: Option<Uuid>,
    metadata: serde_json::Value,
    created_at: time::OffsetDateTime,
}

impl From<FilaAuditLog> for AuditLogEntry {
    fn from(f: FilaAuditLog) -> Self {
        AuditLogEntry {
            id: f.id,
            actor_user_id: f.actor_user_id,
            actor_email: f.actor_email,
            event_type: f.event_type,
            subject_type: f.subject_type,
            subject_id: f.subject_id,
            metadata: f.metadata,
            created_at: f.created_at,
        }
    }
}

impl AuditLogRepository for PgAuditLogRepository {
    async fn insertar(&self, evento: EventoAuditoria) -> Result<(), RepoError> {
        sqlx::query!(
            r#"insert into audit_log_entries (actor_user_id, event_type, subject_type, subject_id, metadata)
               values ($1, $2, $3, $4, $5)"#,
            evento.actor_user_id,
            evento.event_type.as_db_str(),
            evento.subject_type,
            evento.subject_id,
            evento.metadata,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn listar(
        &self,
        filtro: &FiltroAuditLog,
        cursor: Option<Uuid>,
        limite: i64,
    ) -> Result<Vec<AuditLogEntry>, RepoError> {
        let event_type = filtro.event_type.map(|e| e.as_db_str());
        let filas = sqlx::query_as!(
            FilaAuditLog,
            r#"
            select ael.id, ael.actor_user_id, u.email as "actor_email?", ael.event_type,
                   ael.subject_type, ael.subject_id, ael.metadata, ael.created_at
            from audit_log_entries ael
            left join users u on u.id = ael.actor_user_id
            where ($1::uuid is null or ael.id < $1)
              and ($2::uuid is null or ael.actor_user_id = $2)
              and ($3::text is null or ael.event_type = $3)
              and ($4::timestamptz is null or ael.created_at >= $4)
              and ($5::timestamptz is null or ael.created_at <= $5)
            order by ael.id desc
            limit $6
            "#,
            cursor,
            filtro.actor_user_id,
            event_type,
            filtro.desde,
            filtro.hasta,
            limite,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(filas.into_iter().map(AuditLogEntry::from).collect())
    }

    async fn listar_para_exportar(&self, filtro: &FiltroAuditLog) -> Result<Vec<AuditLogEntry>, RepoError> {
        let event_type = filtro.event_type.map(|e| e.as_db_str());
        let filas = sqlx::query_as!(
            FilaAuditLog,
            r#"
            select ael.id, ael.actor_user_id, u.email as "actor_email?", ael.event_type,
                   ael.subject_type, ael.subject_id, ael.metadata, ael.created_at
            from audit_log_entries ael
            left join users u on u.id = ael.actor_user_id
            where ($1::uuid is null or ael.actor_user_id = $1)
              and ($2::text is null or ael.event_type = $2)
              and ($3::timestamptz is null or ael.created_at >= $3)
              and ($4::timestamptz is null or ael.created_at <= $4)
            order by ael.id asc
            limit $5
            "#,
            filtro.actor_user_id,
            event_type,
            filtro.desde,
            filtro.hasta,
            LIMITE_EXPORT_MAXIMO,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(filas.into_iter().map(AuditLogEntry::from).collect())
    }
}
