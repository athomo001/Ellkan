// Autor: Athan Espinoza

//! Job programado (F-26): quema (borra `ciphertext`) shares vencidos que
//! nadie llegó a abrir nunca — el acceso normal (`acceder`) ya quema
//! on-the-fly al detectar `expires_at` vencido, pero un share que nadie
//! abre nunca no dispara ese camino. Intervalo corto (no diario, como
//! `retention::job`) porque la expiración por defecto de un share es del
//! orden de horas, no meses — dejar el ciphertext colgando un día entero
//! violaría el requisito de borrado efectivo casi tanto como no borrarlo.

use std::time::Duration;

use crate::audit::models::{AuditEventType, EventoAuditoria};
use crate::eventos::{DomainEvent, EmisorDeEventos};

use super::repository::{ExternalShareRepository, PgExternalShareRepository};

pub fn spawn(eventos: &EmisorDeEventos, shares: PgExternalShareRepository, intervalo: Duration) {
    let eventos = eventos.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(intervalo);
        loop {
            ticker.tick().await;
            match shares.quemar_expirados().await {
                Ok(quemados) => {
                    for id in quemados {
                        let _ = eventos.send(DomainEvent::Auditoria(
                            EventoAuditoria::nuevo(AuditEventType::ExternalShareBurned, None)
                                .con_sujeto("external_share", id)
                                .con_metadata(serde_json::json!({ "reason": "expired" })),
                        ));
                    }
                }
                Err(e) => tracing::error!(error = %e, "el barrido de external shares vencidos falló"),
            }
        }
    });
}
