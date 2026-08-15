// Autor: Athan Espinoza

//! Job programado de purga (F-40) — corre en un intervalo fijo, sin cursor
//! propio (mismo criterio que el resto de los jobs de background de
//! Ellkan): cada corrida es idempotente, sólo actúa sobre lo que siga
//! vencido en ese momento.

use std::time::Duration;

use crate::audit::models::{AuditEventType, EventoAuditoria};
use crate::eventos::{DomainEvent, EmisorDeEventos};

use super::repository::{PgPurgeRepository, PgRetentionPolicyRepository, PurgeRepository, RetentionPolicyRepository};

pub fn spawn(
    eventos: &EmisorDeEventos,
    policy: PgRetentionPolicyRepository,
    purga: PgPurgeRepository,
    intervalo: Duration,
) {
    let eventos = eventos.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(intervalo);
        loop {
            ticker.tick().await;
            let politica = match policy.obtener().await {
                Ok(p) => p,
                Err(e) => {
                    tracing::error!(error = %e, "no se pudo leer la política de retención");
                    continue;
                }
            };
            match purga.purgar(politica.data_retention_days, politica.audit_log_retention_days).await {
                Ok(resultado) => {
                    let _ = eventos.send(DomainEvent::Auditoria(
                        EventoAuditoria::nuevo(AuditEventType::RetentionPurgeRan, None).con_metadata(
                            serde_json::json!({
                                "resources": resultado.resources,
                                "folders": resultado.folders,
                                "tags": resultado.tags,
                                "groups": resultado.groups,
                                "user_totp_credentials": resultado.user_totp_credentials,
                                "audit_log_entries": resultado.audit_log_entries,
                            }),
                        ),
                    ));
                }
                Err(e) => tracing::error!(error = %e, "la corrida del job de purga falló"),
            }
        }
    });
}
