// Autor: Athan Espinoza

//! Consumidor dedicado de `DomainEvent::Auditoria` (F-13) — corre en su
//! propia tarea `tokio`, suscripto al mismo bus que `notificaciones` y
//! `metadata::rotacion`. El service que emite el evento sigue de inmediato;
//! si esta escritura fallara, nunca tumba la operación real que audita
//! (mismo criterio ya aplicado a la cola de emails).

use crate::eventos::{recibir_tolerando_lag, DomainEvent, EmisorDeEventos};

use super::repository::AuditLogRepository;

pub fn spawn_consumidor<A>(eventos: &EmisorDeEventos, audit_log: A)
where
    A: AuditLogRepository + Send + Sync + 'static,
{
    let mut receptor = eventos.subscribe();
    tokio::spawn(async move {
        while let Some(evento) = recibir_tolerando_lag(&mut receptor, "audit").await {
            if let DomainEvent::Auditoria(entrada) = evento
                && let Err(e) = audit_log.insertar(entrada).await
            {
                tracing::error!(error = %e, "no se pudo persistir una entrada de audit_log_entries");
            }
        }
    });
}
