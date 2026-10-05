// Autor: Athan Espinoza

//! F-47: avisos en vivo a la app de escritorio vinculada. En vez de que la app
//! pregunte "¿hay algo nuevo?" cada pocos segundos, el servidor le avisa por
//! una conexión abierta (`GET /sync/eventos`, Server-Sent Events) cuando cambia
//! algo que le toca; recién ahí la app pide el delta con `GET /sync`.
//!
//! El aviso no lleva datos: sólo "hubo un cambio para vos". Lo arma un
//! consumidor del bus de eventos a partir de las entradas de auditoría sobre
//! recursos, carpetas y tags: avisa a quien hizo la acción (sus otros
//! dispositivos) y, si es un recurso, a todos sus destinatarios. Lo que no
//! llegue por acá (por ejemplo, el borrado de un recurso compartido, cuyos
//! destinatarios ya no existen al momento del aviso) lo trae el sync de
//! respaldo que la app sigue haciendo cada pocos minutos.

use std::collections::HashSet;
use std::convert::Infallible;
use std::time::Duration;

use axum::extract::State;
use axum::response::sse::{Event, KeepAlive, Sse};
use futures_util::Stream;
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::auth::extractor::AuthenticatedUser;
use crate::eventos::{recibir_tolerando_lag, DomainEvent, EmisorDeEventos};
use crate::resources::repository::{PgResourceRepository, ResourceRepository};
use crate::state::AppState;

/// Canal interno: cada mensaje es el id de un usuario al que hay que avisar.
pub type CanalAvisos = broadcast::Sender<Uuid>;

pub fn nuevo_canal() -> CanalAvisos {
    broadcast::channel(1024).0
}

/// Cada cuánto se cierra una conexión de avisos: la app reconecta y vuelve a
/// autenticar, así una sesión revocada o vencida no queda escuchando para siempre.
const VIDA_CONEXION: Duration = Duration::from_secs(10 * 60);

pub fn spawn_consumidor(eventos: &EmisorDeEventos, recursos: PgResourceRepository, avisos: CanalAvisos) {
    let mut receptor = eventos.subscribe();
    tokio::spawn(async move {
        while let Some(evento) = recibir_tolerando_lag(&mut receptor, "sync_avisos").await {
            let DomainEvent::Auditoria(entrada) = evento else { continue };
            if !matches!(entrada.subject_type, Some("resource" | "folder" | "tag")) {
                continue;
            }
            let mut usuarios: HashSet<Uuid> = entrada.actor_user_id.into_iter().collect();
            if entrada.subject_type == Some("resource")
                && let Some(id) = entrada.subject_id
                && let Ok(destinatarios) = recursos.listar_destinatarios(id).await
            {
                usuarios.extend(destinatarios.into_iter().map(|d| d.user_id));
            }
            for usuario in usuarios {
                // Sin nadie escuchando, `send` devuelve error: no es un problema.
                let _ = avisos.send(usuario);
            }
        }
    });
}

fn aviso() -> Result<Event, Infallible> {
    Ok(Event::default().event("cambio").data("1"))
}

/// `GET /sync/eventos` — Server-Sent Events, sólo con los avisos del usuario
/// autenticado. Se cierra sola a los `VIDA_CONEXION`; un `keep-alive` cada 20 s
/// evita que un proxy la corte por inactividad.
pub async fn eventos(State(state): State<AppState>, auth: AuthenticatedUser) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let receptor = state.avisos_sync.subscribe();
    let usuario = auth.user_id;
    let fin = tokio::time::Instant::now() + VIDA_CONEXION;
    let flujo = futures_util::stream::unfold(receptor, move |mut receptor| async move {
        loop {
            match tokio::time::timeout_at(fin, receptor.recv()).await {
                Err(_) | Ok(Err(broadcast::error::RecvError::Closed)) => return None,
                Ok(Ok(destino)) if destino == usuario => return Some((aviso(), receptor)),
                Ok(Ok(_)) => continue,
                // Se perdieron avisos (ráfaga): avisar igual, el delta de `/sync` pone todo al día.
                Ok(Err(broadcast::error::RecvError::Lagged(_))) => return Some((aviso(), receptor)),
            }
        }
    });
    Sse::new(flujo).keep_alive(KeepAlive::new().interval(Duration::from_secs(20)))
}
