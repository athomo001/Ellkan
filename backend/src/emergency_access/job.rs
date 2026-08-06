// Autor: Athan Espinoza

//! Job programado (F-36): resuelve `granted_by_timeout` cuando
//! `requested_at + wait_time_days` vence sin respuesta del titular — sin
//! esto, un titular inaccesible (el escenario mismo que Emergency Access
//! existe para cubrir) dejaría al contacto esperando para siempre.

use std::time::Duration;

use crate::audit::models::{AuditEventType, EventoAuditoria};
use crate::eventos::{DomainEvent, EmisorDeEventos};

use super::repository::{
    EmergencyAccessRepository, EmergencyAccessRequestRepository, PgEmergencyAccessRepository,
    PgEmergencyAccessRequestRepository,
};

/// Tipos concretos (no genéricos) a propósito: el trait usa `async fn` sin
/// bound `Send` explícito en la firma (`#![allow(async_fn_in_trait)]`), así
/// que el compilador no puede probar que el future de una implementación
/// genérica es `Send` para `tokio::spawn` — con el tipo `Pg*` concreto sí lo
/// prueba, porque los futures reales de `sqlx` son `Send`.
pub fn spawn(
    eventos: &EmisorDeEventos,
    accesos: PgEmergencyAccessRepository,
    requests: PgEmergencyAccessRequestRepository,
    intervalo: Duration,
) {
    let eventos = eventos.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(intervalo);
        loop {
            ticker.tick().await;
            let vencidas = match requests.listar_vencidas().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!(error = %e, "no se pudo listar solicitudes de emergency access vencidas");
                    continue;
                }
            };
            for (solicitud, granter_id) in vencidas {
                if let Err(e) = requests.resolver(solicitud.id, "granted_by_timeout").await {
                    tracing::error!(error = %e, request_id = %solicitud.id, "no se pudo resolver por timeout");
                    continue;
                }
                if let Err(e) = accesos.marcar_status(solicitud.emergency_access_id, "confirmed").await {
                    tracing::error!(error = %e, "no se pudo marcar emergency_access como confirmed");
                }
                let _ = eventos.send(DomainEvent::Auditoria(
                    EventoAuditoria::nuevo(AuditEventType::EmergencyAccessGrantedByTimeout, Some(granter_id))
                        .con_sujeto("emergency_access", solicitud.emergency_access_id),
                ));
            }
        }
    });
}
