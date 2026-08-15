// Autor: Athan Espinoza

//! Service de auditoría — nunca importa `axum`. La autorización (permiso
//! `audit_log.read`) ya la resuelve el extractor `AuditorUser` en el
//! Controller, igual criterio que `MetadataKeyService` con `AdminUser`.

use uuid::Uuid;

use crate::error::DomainError;

use super::models::{AuditLogEntry, FiltroAuditLog};
use super::repository::{AuditLogRepository, LIMITE_PAGINA_DEFAULT, LIMITE_PAGINA_MAXIMO};

pub struct AuditLogService<'a, A> {
    pub audit_log: &'a A,
}

/// Página de resultados — `next_cursor` es `None` cuando no hay más
/// entradas más viejas que las ya devueltas.
pub struct PaginaAuditLog {
    pub items: Vec<AuditLogEntry>,
    pub next_cursor: Option<Uuid>,
}

impl<'a, A> AuditLogService<'a, A>
where
    A: AuditLogRepository,
{
    pub async fn listar(
        &self,
        filtro: FiltroAuditLog,
        cursor: Option<Uuid>,
        limite: Option<i64>,
    ) -> Result<PaginaAuditLog, DomainError> {
        let limite = limite.unwrap_or(LIMITE_PAGINA_DEFAULT).clamp(1, LIMITE_PAGINA_MAXIMO);

        // Se pide una fila de más: si vuelve, hay una página siguiente de
        // verdad y se descarta esa fila extra antes de responder — evita el
        // caso borde de asumir "hay más" cuando la página completa esta
        // página exactamente y no queda ninguna otra atrás.
        let mut items = self.audit_log.listar(&filtro, cursor, limite + 1).await?;

        let next_cursor = if items.len() as i64 > limite {
            items.pop();
            items.last().map(|e| e.id)
        } else {
            None
        };

        Ok(PaginaAuditLog { items, next_cursor })
    }

    /// `GET /admin/audit-log/export` — sin paginación, orden cronológico
    /// ascendente, techo duro en el repository (`LIMITE_EXPORT_MAXIMO`).
    pub async fn exportar(&self, filtro: FiltroAuditLog) -> Result<Vec<AuditLogEntry>, DomainError> {
        Ok(self.audit_log.listar_para_exportar(&filtro).await?)
    }
}
