// Autor: Athan Espinoza

//! Consulta diaria. Corre siempre, pero no sale a la red si el aviso está
//! apagado (el default): `consultar_si_corresponde` lo mira cada vez.

use std::time::Duration;

use crate::eventos::EmisorDeEventos;

use super::repository::PgUpdateCheckRepository;
use super::service::UpdateCheckService;

const CADA: Duration = Duration::from_secs(24 * 60 * 60);
/// La primera vuelta espera un poco: el arranque no depende de GitHub.
const PRIMERA_ESPERA: Duration = Duration::from_secs(60);

pub fn lanzar(repo: PgUpdateCheckRepository, eventos: EmisorDeEventos) {
    tokio::spawn(async move {
        tokio::time::sleep(PRIMERA_ESPERA).await;
        let mut ticker = tokio::time::interval(CADA);
        loop {
            ticker.tick().await;
            let servicio = UpdateCheckService { repo: &repo, eventos: eventos.clone() };
            if let Err(e) = servicio.consultar_si_corresponde().await {
                tracing::warn!("aviso de versión: {e:?}");
            }
        }
    });
}
