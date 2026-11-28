// Autor: Athan Espinoza

//! spec/15 §2 (pendiente #53): sincronización automática con el directorio.
//! Cada 15 s mira si le toca (`auto_sync_enabled` y pasaron
//! `poll_interval_seconds` desde la última); la que logra mover
//! `last_sync_at` corre, así dos réplicas nunca sincronizan a la vez. Corre el
//! mismo «aplicar» que el botón del panel, con el freno de bajas masivas
//! (§2.5): la corrida automática nunca lo confirma, sólo audita y avisa.

use std::time::Duration;

use crate::state::AppState;

use super::repository::DirectorySyncConfigRepository;

pub fn spawn(estado: AppState) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(15));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            match estado.directory_sync_config.tomar_corrida_automatica().await {
                Ok(true) => {}
                Ok(false) => continue,
                Err(e) => {
                    tracing::warn!(error = %e, "directory sync automático: no se pudo leer la configuración");
                    continue;
                }
            }
            let resultado = super::handlers::servicio(&estado).aplicar(None, false).await;
            let error = match &resultado {
                Ok(r) if r.aborted => Some(format!(
                    "corrida abortada: desactivaría {} cuentas (más que el tope); revisá el dry-run y aplicá a mano si es correcto",
                    r.would_deactivate.len()
                )),
                Ok(_) => None,
                Err(e) => Some(e.to_string()),
            };
            if let Some(e) = &error {
                tracing::warn!(error = %e, "directory sync automático");
            }
            if let Err(e) = estado.directory_sync_config.anotar_error_automatico(error.as_deref()).await {
                tracing::warn!(error = %e, "directory sync automático: no se pudo anotar el resultado");
            }
        }
    });
}
