// Autor: Athan Espinoza

//! Job de background de F-33: vigila una rotación en curso y expira la clave
//! saliente en cuanto ningún recurso activo sigue referenciándola. El
//! re-cifrado en sí (`POST /resources/{id}/rekey-metadata`) lo hace un
//! cliente con acceso a la metadata en claro — este job nunca descifra
//! nada, sólo cuenta filas y decide cuándo la migración terminó.
//!
//! Sin estado propio en memoria más allá del intervalo de polling: si el
//! proceso se reinicia a mitad de una rotación, `reconciliar_al_arrancar`
//! vuelve a vigilar exactamente la misma rotación (detectada por "hay 2
//! claves activas") sin perder ni reprocesar nada — el progreso siempre se
//! recalcula en vivo contra `resources`, nunca se guarda un cursor.

use std::time::Duration;

use tracing::info;

use crate::eventos::{recibir_tolerando_lag, DomainEvent, EmisorDeEventos};

use super::repository::MetadataKeyRepository;

const INTERVALO_POLLING: Duration = Duration::from_millis(200);

async fn vigilar_hasta_completar<K: MetadataKeyRepository>(claves: K, saliente_id: uuid::Uuid) {
    loop {
        match claves.contar_recursos_con_clave(saliente_id).await {
            Ok(0) => {
                if claves.marcar_expirada(saliente_id).await.is_ok() {
                    info!(saliente_id = %saliente_id, "rotación de metadata key completada");
                }
                return;
            }
            Ok(_pendientes) => {}
            // Error transitorio de DB — reintenta en el próximo tick en vez
            // de abandonar la vigilancia de la rotación.
            Err(_) => {}
        }
        tokio::time::sleep(INTERVALO_POLLING).await;
    }
}

pub fn spawn_consumidor<K>(eventos: &EmisorDeEventos, claves: K)
where
    K: MetadataKeyRepository + Clone + Send + Sync + 'static,
{
    let mut receptor = eventos.subscribe();
    tokio::spawn(async move {
        while let Some(evento) = recibir_tolerando_lag(&mut receptor, "metadata_rotacion").await {
            if let DomainEvent::MetadataKeyRotationStarted { saliente_id, .. } = evento {
                tokio::spawn(vigilar_hasta_completar(claves.clone(), saliente_id));
            }
        }
    });
}

/// Si el servidor arranca con una rotación ya en curso (2 claves activas —
/// el proceso anterior se cayó a mitad de camino), retoma la vigilancia sin
/// que nadie tenga que volver a llamar `POST /admin/metadata-keys/rotate`.
pub async fn reconciliar_al_arrancar<K>(claves: K)
where
    K: MetadataKeyRepository + Clone + Send + Sync + 'static,
{
    if let Ok(activas) = claves.activas().await
        && let [a, b] = activas.as_slice()
    {
        let saliente_id = if a.resources_pendientes_al_iniciar.is_some() { a.id } else { b.id };
        tokio::spawn(vigilar_hasta_completar(claves, saliente_id));
    }
}
