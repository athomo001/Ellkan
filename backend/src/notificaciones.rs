// Autor: Athan Espinoza

//! Cola de notificaciones por email: tabla en Postgres, sin broker externo,
//! nunca síncrono dentro del request. El consumidor de eventos escribe la
//! fila; un poller aparte la procesa.
//!
//! **Envío real de SMTP queda pendiente** (decisión explícita del usuario):
//! el poller de acá es un stub que loguea y marca `enviado` — la
//! arquitectura (evento → cola → consumidor) queda lista para reemplazar el
//! cuerpo de `procesar_pendientes` por una llamada SMTP real más adelante,
//! sin tocar el resto.
use std::future::Future;
use std::time::Duration;

use crate::error::RepoError;
use crate::eventos::{DomainEvent, EmisorDeEventos};

// A diferencia de los repositories de `auth`/`resources` (genéricos, sin
// `dyn`, nunca cruzan un `tokio::spawn`), acá el future SÍ necesita ser
// `Send` explícito: los consumidores de este trait corren dentro de tareas
// spawneadas, y `async fn` en un trait no garantiza `Send` por sí solo.
pub trait OutboundEmailRepository {
    fn encolar(&self, recipient: &str, subject: &str, body: &str) -> impl Future<Output = Result<(), RepoError>> + Send;
    /// Devuelve cuántas filas `pendiente` se marcaron `enviado` — el stub de
    /// Fase 0 no necesita leer el cuerpo, un consumidor SMTP real sí.
    fn marcar_pendientes_como_enviadas(&self) -> impl Future<Output = Result<u64, RepoError>> + Send;
}

#[derive(Clone)]
pub struct PgOutboundEmailRepository {
    pub pool: sqlx::PgPool,
}

impl OutboundEmailRepository for PgOutboundEmailRepository {
    async fn encolar(&self, recipient: &str, subject: &str, body: &str) -> Result<(), RepoError> {
        sqlx::query!(
            r#"insert into outbound_emails (recipient, subject, body) values ($1, $2, $3)"#,
            recipient,
            subject,
            body,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn marcar_pendientes_como_enviadas(&self) -> Result<u64, RepoError> {
        let resultado = sqlx::query!(
            r#"update outbound_emails set status = 'enviado', sent_at = now()
               where status = 'pendiente'"#,
        )
        .execute(&self.pool)
        .await?;
        Ok(resultado.rows_affected())
    }
}

/// Consumidor de `DomainEvent` — se suscribe al broadcast y encola el email
/// correspondiente. Corre en su propia tarea `tokio`, nunca bloquea el
/// request que emitió el evento.
pub fn spawn_consumidor_de_eventos<E>(eventos: &EmisorDeEventos, emails: E)
where
    E: OutboundEmailRepository + Send + Sync + 'static,
{
    let mut receptor = eventos.subscribe();
    tokio::spawn(async move {
        while let Ok(evento) = receptor.recv().await {
            match evento {
                DomainEvent::DispositivoNoReconocido { email, codigo, .. } => {
                    let asunto = "Ellkan: verificá este dispositivo nuevo";
                    let cuerpo = format!(
                        "Detectamos un inicio de sesión desde un dispositivo no reconocido.\n\
                         Código de verificación: {codigo}\n\
                         Si no fuiste vos, ignorá este email."
                    );
                    if let Err(e) = emails.encolar(&email, asunto, &cuerpo).await {
                        tracing::error!(error = %e, "no se pudo encolar el email de verificación de dispositivo");
                    }
                }
            }
        }
    });
}

/// Poller stub — Fase 1 reemplaza el cuerpo de este `tick` por un envío SMTP
/// real; el `interval` y el ciclo de vida de la tarea no cambian.
pub fn spawn_poller_de_envio<E>(emails: E, intervalo: Duration)
where
    E: OutboundEmailRepository + Send + Sync + 'static,
{
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(intervalo);
        loop {
            ticker.tick().await;
            match emails.marcar_pendientes_como_enviadas().await {
                Ok(0) => {}
                Ok(n) => tracing::debug!(cantidad = n, "emails marcados como enviados (stub, sin SMTP real)"),
                Err(e) => tracing::error!(error = %e, "fallo el poller de envío de emails"),
            }
        }
    });
}
