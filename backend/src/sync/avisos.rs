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
use std::sync::Arc;
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

/// Mensaje del canal interno de avisos.
#[derive(Debug, Clone)]
pub enum AvisoSync {
    /// Hubo un cambio para este usuario: la app pide el delta de `/sync`.
    Cambio(Uuid),
    /// La cuenta fue bloqueada o purgada (docs/revocacion-remota.md): se le
    /// manda a la app el aviso FIRMADO por el servidor y se cierra el stream.
    Revocada { user_id: Uuid, aviso: Arc<crate::revocacion::AvisoFirmado> },
}

/// Canal interno de avisos para las apps de escritorio conectadas.
pub type CanalAvisos = broadcast::Sender<AvisoSync>;

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
                let _ = avisos.send(AvisoSync::Cambio(usuario));
            }
        }
    });
}

fn aviso() -> Result<Event, Infallible> {
    Ok(Event::default().event("cambio").data("1"))
}

/// `event: cuenta_revocada` con el aviso firmado (`{aviso, firma_b64}`) en `data`.
fn aviso_revocada(firmado: &crate::revocacion::AvisoFirmado) -> Result<Event, Infallible> {
    let datos = serde_json::to_string(firmado).unwrap_or_default();
    Ok(Event::default().event("cuenta_revocada").data(datos))
}

/// `GET /sync/eventos` — Server-Sent Events, sólo con los avisos del usuario
/// autenticado. Se cierra sola a los `VIDA_CONEXION`; un `keep-alive` cada 20 s
/// evita que un proxy la corte por inactividad. Si la cuenta se revoca, manda
/// el aviso firmado y se cierra en el acto.
pub async fn eventos(State(state): State<AppState>, auth: AuthenticatedUser) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let receptor = state.avisos_sync.subscribe();
    let usuario = auth.user_id;
    let fin = tokio::time::Instant::now() + VIDA_CONEXION;
    // Estado: (receptor, ya se mandó la revocación → cortar en el próximo paso).
    let flujo = futures_util::stream::unfold((receptor, false), move |(mut receptor, revocada)| async move {
        if revocada {
            return None;
        }
        loop {
            match tokio::time::timeout_at(fin, receptor.recv()).await {
                Err(_) | Ok(Err(broadcast::error::RecvError::Closed)) => return None,
                Ok(Ok(AvisoSync::Cambio(destino))) if destino == usuario => return Some((aviso(), (receptor, false))),
                Ok(Ok(AvisoSync::Revocada { user_id, aviso })) if user_id == usuario => {
                    return Some((aviso_revocada(&aviso), (receptor, true)));
                }
                Ok(Ok(_)) => continue,
                // Se perdieron avisos (ráfaga): avisar igual, el delta de `/sync` pone todo al día.
                // Una revocación perdida la recupera la app con `POST /auth/estado-cuenta`
                // cuando la re-autenticación falle.
                Ok(Err(broadcast::error::RecvError::Lagged(_))) => return Some((aviso(), (receptor, false))),
            }
        }
    });
    Sse::new(flujo).keep_alive(KeepAlive::new().interval(Duration::from_secs(20)))
}
