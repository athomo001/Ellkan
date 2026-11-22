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

use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State;
use axum::response::sse::{Event, KeepAlive, Sse};
use futures_util::Stream;
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::auth::extractor::AuthenticatedUser;
use crate::auth::repository::SessionRepository;
use crate::error::{ApiError, DomainError};
use crate::eventos::{DomainEvent, EmisorDeEventos, recibir_tolerando_lag};
use crate::resources::repository::{PgResourceRepository, ResourceRepository};
use crate::state::AppState;

/// Mensaje del canal interno de avisos.
#[derive(Debug, Clone)]
pub enum AvisoSync {
    /// Hubo un cambio para este usuario: la app pide el delta de `/sync`.
    Cambio(Uuid),
    /// La cuenta fue bloqueada o purgada (docs/revocacion-remota.md): se le
    /// manda a la app el aviso FIRMADO por el servidor y se cierra el stream.
    Revocada {
        user_id: Uuid,
        aviso: Arc<crate::revocacion::AvisoFirmado>,
    },
}

/// Canal interno de avisos para las apps de escritorio conectadas.
pub type CanalAvisos = broadcast::Sender<AvisoSync>;

pub fn nuevo_canal() -> CanalAvisos {
    broadcast::channel(1024).0
}

/// Cada cuánto se cierra una conexión de avisos: la app reconecta y vuelve a
/// autenticar, así una sesión revocada o vencida no queda escuchando para siempre.
const VIDA_CONEXION: Duration = Duration::from_secs(10 * 60);

/// QA-39: cada cuánto se vuelve a validar la sesión de una conexión abierta.
/// Una sesión cerrada («Cerrar las demás»), revocada o vencida deja de
/// recibir avisos a más tardar en este plazo, no a los 10 minutos.
const REVALIDAR_SESION: Duration = Duration::from_secs(60);

/// QA-39: conexiones de avisos simultáneas por usuario. Alcanza de sobra
/// para la app, la web y la extensión en varios equipos; más que esto es un
/// cliente roto o abuso (cada conexión es una tarea y un receptor del canal).
pub const MAX_CONEXIONES_POR_USUARIO: u32 = 10;

/// Contador de conexiones abiertas por usuario.
pub type ConexionesPorUsuario = Arc<Mutex<HashMap<Uuid, u32>>>;

/// Ocupa un lugar en el contador mientras vive (el stream SSE lo guarda); al
/// cerrarse la conexión por cualquier motivo, `Drop` lo libera.
struct LugarDeConexion {
    conexiones: ConexionesPorUsuario,
    usuario: Uuid,
}

impl LugarDeConexion {
    fn ocupar(conexiones: &ConexionesPorUsuario, usuario: Uuid) -> Option<Self> {
        let mut mapa = conexiones.lock().unwrap_or_else(|e| e.into_inner());
        let abiertas = mapa.entry(usuario).or_insert(0);
        if *abiertas >= MAX_CONEXIONES_POR_USUARIO {
            return None;
        }
        *abiertas += 1;
        Some(Self { conexiones: conexiones.clone(), usuario })
    }
}

impl Drop for LugarDeConexion {
    fn drop(&mut self) {
        let mut mapa = self.conexiones.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(abiertas) = mapa.get_mut(&self.usuario) {
            *abiertas -= 1;
            if *abiertas == 0 {
                mapa.remove(&self.usuario);
            }
        }
    }
}

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
/// autenticado. Se cierra sola a los `VIDA_CONEXION`, o antes si la sesión deja
/// de ser válida (se revisa cada `REVALIDAR_SESION`); un `keep-alive` cada 20 s
/// evita que un proxy la corte por inactividad. Si la cuenta se revoca, manda
/// el aviso firmado y se cierra en el acto. 429 si el usuario ya tiene
/// `MAX_CONEXIONES_POR_USUARIO` abiertas.
pub async fn eventos(
    State(state): State<AppState>,
    auth: AuthenticatedUser,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, ApiError> {
    let usuario = auth.user_id;
    let lugar = LugarDeConexion::ocupar(&state.conexiones_sse, usuario).ok_or(DomainError::RateLimited)?;
    let receptor = state.avisos_sync.subscribe();
    let sesiones = state.sesiones.clone();
    let session_id = auth.session_id;
    let fin = tokio::time::Instant::now() + VIDA_CONEXION;
    let estado_inicial = Conexion {
        receptor,
        revocada: false,
        revisar_sesion: tokio::time::Instant::now() + REVALIDAR_SESION,
        _lugar: lugar,
    };
    let flujo = futures_util::stream::unfold(estado_inicial, move |mut c| {
        let sesiones = sesiones.clone();
        async move {
            if c.revocada {
                return None;
            }
            loop {
                match tokio::time::timeout_at(fin.min(c.revisar_sesion), c.receptor.recv()).await {
                    Err(_) if tokio::time::Instant::now() >= fin => return None,
                    Err(_) => {
                        // Revisión periódica: sesión cerrada, revocada o vencida
                        // (o error de base, por las dudas) → se corta.
                        if !matches!(sesiones.validar(session_id).await, Ok(Some(_))) {
                            return None;
                        }
                        c.revisar_sesion = tokio::time::Instant::now() + REVALIDAR_SESION;
                    }
                    Ok(Err(broadcast::error::RecvError::Closed)) => return None,
                    Ok(Ok(AvisoSync::Cambio(destino))) if destino == usuario => return Some((aviso(), c)),
                    Ok(Ok(AvisoSync::Revocada { user_id, aviso })) if user_id == usuario => {
                        c.revocada = true;
                        return Some((aviso_revocada(&aviso), c));
                    }
                    Ok(Ok(_)) => continue,
                    // Se perdieron avisos (ráfaga): avisar igual, el delta de `/sync` pone todo al día.
                    // Una revocación perdida la recupera la app con `POST /auth/estado-cuenta`
                    // cuando la re-autenticación falle.
                    Ok(Err(broadcast::error::RecvError::Lagged(_))) => return Some((aviso(), c)),
                }
            }
        }
    });
    Ok(Sse::new(flujo).keep_alive(KeepAlive::new().interval(Duration::from_secs(20))))
}

/// Estado de una conexión de avisos abierta.
struct Conexion {
    receptor: broadcast::Receiver<AvisoSync>,
    /// Ya se mandó la revocación: cortar en el próximo paso.
    revocada: bool,
    revisar_sesion: tokio::time::Instant,
    /// Libera el lugar en el tope por usuario al cerrarse la conexión.
    _lugar: LugarDeConexion,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn el_tope_por_usuario_se_libera_al_cerrar() {
        let conexiones = ConexionesPorUsuario::default();
        let usuario = Uuid::now_v7();
        let lugares: Vec<_> = (0..MAX_CONEXIONES_POR_USUARIO)
            .map(|_| LugarDeConexion::ocupar(&conexiones, usuario).unwrap())
            .collect();
        assert!(LugarDeConexion::ocupar(&conexiones, usuario).is_none(), "una de más se rechaza");
        assert!(LugarDeConexion::ocupar(&conexiones, Uuid::now_v7()).is_some(), "otro usuario no se ve afectado");
        drop(lugares);
        let otro_lugar = LugarDeConexion::ocupar(&conexiones, usuario);
        assert!(otro_lugar.is_some());
        assert_eq!(conexiones.lock().unwrap().get(&usuario), Some(&1));
        drop(otro_lugar);
        assert!(conexiones.lock().unwrap().get(&usuario).is_none(), "sin conexiones no queda la entrada");
    }
}
