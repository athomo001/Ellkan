// Autor: Athan Espinoza

//! Cola de notificaciones por email: tabla en Postgres, sin broker externo,
//! nunca síncrono dentro del request. El consumidor de eventos escribe la
//! fila; un poller aparte la procesa.
//!
//! **Envío real de SMTP** (`smtp_config` configurada desde el admin, Parte
//! A — reemplaza el `ELLKAN_SMTP_*` por variable de entorno que este módulo
//! tenía antes): el poller relee la config en cada tick y manda cada email
//! pendiente vía SMTP de verdad. **Sin configurar**: se mantiene el stub
//! original, que sólo marca `enviado` sin mandar nada — la arquitectura
//! (evento → cola → consumidor) es la misma en los dos casos, sólo cambia
//! el cuerpo del `tick`.
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use uuid::Uuid;

use ellkan_crypto::secretos::ClaveSecreta32;

use crate::error::RepoError;
use crate::eventos::{DomainEvent, EmisorDeEventos};
use crate::smtp_config::repository::SmtpConfigRepository;

/// Fila lista para enviar — a diferencia del stub original, acá sí hace
/// falta leer el cuerpo completo, no sólo marcar la fila.
#[derive(Debug, Clone)]
pub struct EmailPendiente {
    pub id: Uuid,
    pub recipient: String,
    pub subject: String,
    pub body: String,
}

// A diferencia de los repositories de `auth`/`resources` (genéricos, sin
// `dyn`, nunca cruzan un `tokio::spawn`), acá el future SÍ necesita ser
// `Send` explícito: los consumidores de este trait corren dentro de tareas
// spawneadas, y `async fn` en un trait no garantiza `Send` por sí solo.
pub trait OutboundEmailRepository {
    /// Devuelve el `id` de la fila insertada — usado por `SmtpConfigService::probar_envio`
    /// (Parte C) para hacer polling puntual de esa fila sin ambigüedad de
    /// `recipient` repetido; el consumidor de eventos ignora el valor.
    fn encolar(&self, recipient: &str, subject: &str, body: &str) -> impl Future<Output = Result<Uuid, RepoError>> + Send;
    /// Estado de una fila puntual por `id` — sólo para el polling de
    /// `probar_envio`, el poller real de envío usa `tomar_pendientes`.
    fn estado_de(&self, id: Uuid) -> impl Future<Output = Result<Option<String>, RepoError>> + Send;
    /// Stub de Fase 0/dev sin SMTP configurado: marca todo lo `pendiente`
    /// como `enviado` sin leer el cuerpo ni mandar nada.
    fn marcar_pendientes_como_enviadas(&self) -> impl Future<Output = Result<u64, RepoError>> + Send;
    /// SMTP real: trae hasta `limite` filas `pendiente` para enviar de verdad.
    fn tomar_pendientes(&self, limite: i64) -> impl Future<Output = Result<Vec<EmailPendiente>, RepoError>> + Send;
    fn marcar_enviada(&self, id: Uuid) -> impl Future<Output = Result<(), RepoError>> + Send;
    /// Incrementa `attempts`; pasado `MAX_INTENTOS` la deja `fallido` en vez
    /// de reintentarla para siempre.
    fn marcar_intento_fallido(&self, id: Uuid) -> impl Future<Output = Result<(), RepoError>> + Send;
    /// `(pendientes, fallidos)` — F-43, backlog para el panel de
    /// autodiagnóstico admin. No cuenta `enviado`, no interesa acá.
    fn contar_por_estado(&self) -> impl Future<Output = Result<(i64, i64), RepoError>> + Send;
}

#[derive(Clone)]
pub struct PgOutboundEmailRepository {
    pub pool: sqlx::PgPool,
}

const MAX_INTENTOS: i32 = 5;

impl OutboundEmailRepository for PgOutboundEmailRepository {
    async fn encolar(&self, recipient: &str, subject: &str, body: &str) -> Result<Uuid, RepoError> {
        let fila = sqlx::query!(
            r#"insert into outbound_emails (recipient, subject, body) values ($1, $2, $3) returning id"#,
            recipient,
            subject,
            body,
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(fila.id)
    }

    async fn estado_de(&self, id: Uuid) -> Result<Option<String>, RepoError> {
        let fila = sqlx::query!(r#"select status from outbound_emails where id = $1"#, id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(fila.map(|f| f.status))
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

    async fn tomar_pendientes(&self, limite: i64) -> Result<Vec<EmailPendiente>, RepoError> {
        let filas = sqlx::query!(
            r#"select id, recipient, subject, body from outbound_emails
               where status = 'pendiente' order by created_at limit $1"#,
            limite,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(filas
            .into_iter()
            .map(|f| EmailPendiente { id: f.id, recipient: f.recipient, subject: f.subject, body: f.body })
            .collect())
    }

    async fn marcar_enviada(&self, id: Uuid) -> Result<(), RepoError> {
        sqlx::query!(r#"update outbound_emails set status = 'enviado', sent_at = now() where id = $1"#, id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn marcar_intento_fallido(&self, id: Uuid) -> Result<(), RepoError> {
        sqlx::query!(
            r#"update outbound_emails set attempts = attempts + 1,
               status = case when attempts + 1 >= $2 then 'fallido' else status end
               where id = $1"#,
            id,
            MAX_INTENTOS,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn contar_por_estado(&self) -> Result<(i64, i64), RepoError> {
        let fila = sqlx::query!(
            r#"select
                 count(*) filter (where status = 'pendiente') as "pendientes!",
                 count(*) filter (where status = 'fallido') as "fallidos!"
               from outbound_emails"#,
        )
        .fetch_one(&self.pool)
        .await?;
        Ok((fila.pendientes, fila.fallidos))
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
                DomainEvent::RegistroPendienteVerificacion { email, codigo, .. } => {
                    let asunto = "Ellkan: verificá tu cuenta";
                    let cuerpo = format!(
                        "Creaste una cuenta en Ellkan.\n\
                         Código de verificación: {codigo}\n\
                         Ingresalo para poder iniciar sesión. Si no fuiste vos, ignorá este email."
                    );
                    if let Err(e) = emails.encolar(&email, asunto, &cuerpo).await {
                        tracing::error!(error = %e, "no se pudo encolar el email de verificación de registro");
                    }
                }
                DomainEvent::MfaCodigoPorCorreo { email, codigo, .. } => {
                    let asunto = "Ellkan: tu código de verificación";
                    let cuerpo = format!(
                        "Alguien (con tu contraseña) está iniciando sesión en Ellkan.\n\
                         Código de verificación: {codigo}\n\
                         Ingresalo para completar el inicio de sesión. Si no fuiste vos, cambiá tu contraseña ahora."
                    );
                    if let Err(e) = emails.encolar(&email, asunto, &cuerpo).await {
                        tracing::error!(error = %e, "no se pudo encolar el email de código MFA");
                    }
                }
                // F-33: consumidor dedicado en `metadata::rotacion`, no
                // genera ninguna notificación por email.
                DomainEvent::MetadataKeyRotationStarted { .. } => {}
                DomainEvent::RecoveryKitResetRequested { email, token, .. } => {
                    let base = std::env::var("ELLKAN_RP_ORIGIN").unwrap_or_else(|_| "http://localhost:8080".to_string());
                    let asunto = "Ellkan: recuperá el acceso a tu cuenta";
                    let cuerpo = format!(
                        "Pediste recuperar el acceso a tu cuenta de Ellkan.\n\
                         Abrí este link y seguí los pasos (vas a necesitar tu recovery kit):\n\
                         {base}/recover?token={token}\n\
                         Este link vence en 1 hora. Si no fuiste vos, ignorá este email — tu cuenta sigue segura."
                    );
                    if let Err(e) = emails.encolar(&email, asunto, &cuerpo).await {
                        tracing::error!(error = %e, "no se pudo encolar el email de reset de recovery kit");
                    }
                }
                DomainEvent::RecoveryKitResetEmailCode { email, codigo, .. } => {
                    let asunto = "Ellkan: tu código de verificación";
                    let cuerpo = format!(
                        "Estás recuperando tu cuenta de Ellkan con tu recovery kit.\n\
                         Código de verificación: {codigo}\n\
                         Ingresalo para completar la recuperación. Si no fuiste vos, ignorá este email."
                    );
                    if let Err(e) = emails.encolar(&email, asunto, &cuerpo).await {
                        tracing::error!(error = %e, "no se pudo encolar el email de código de recovery kit");
                    }
                }
                DomainEvent::RecoveryKitResetCompleted { email, .. } => {
                    let asunto = "Ellkan: tu cuenta se acaba de recuperar";
                    let cuerpo = "Tu cuenta de Ellkan se acaba de recuperar con tu recovery kit y se cerraron \
                                   todas las sesiones activas. Si no fuiste vos, contactá a un administrador de inmediato."
                        .to_string();
                    if let Err(e) = emails.encolar(&email, asunto, &cuerpo).await {
                        tracing::error!(error = %e, "no se pudo encolar el email de aviso de recuperación");
                    }
                }
                DomainEvent::AccountRecoveryAdminNotify { target_email, recipient_emails, .. } => {
                    let asunto = "Ellkan: solicitud de recuperación de cuenta pendiente";
                    let cuerpo = format!(
                        "Hay una solicitud de recuperación de cuenta pendiente para {target_email}.\n\
                         Revisala en el panel de administración."
                    );
                    for destinatario in &recipient_emails {
                        if let Err(e) = emails.encolar(destinatario, asunto, &cuerpo).await {
                            tracing::error!(error = %e, "no se pudo encolar el aviso de solicitud de account recovery");
                        }
                    }
                }
                // F-13: consumidor dedicado en `audit::consumidor`, no
                // genera ninguna notificación por email.
                DomainEvent::Auditoria(_) => {}
            }
        }
    });
}

/// Config SMTP lista para `lettre` — convertida desde `smtp_config::models::SmtpConfig`
/// (la fila de la DB, Parte A) en cada tick del poller, nunca cacheada.
#[derive(Debug, Clone)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub from: String,
    /// STARTTLS + auth (producción) vs. relay local sin cifrar (Mailhog de
    /// dev/test) — nunca hay un default inseguro implícito: el admin lo
    /// tiene que tildar a propósito en `PUT /admin/smtp-config`.
    pub tls: bool,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl SmtpConfig {
    fn desde_db(cfg: &crate::smtp_config::models::SmtpConfig, secrets_key: &ClaveSecreta32) -> Option<Self> {
        if !cfg.esta_configurado() {
            return None;
        }
        Some(Self {
            host: cfg.host.clone()?,
            port: cfg.port.and_then(|p| u16::try_from(p).ok()).unwrap_or(25),
            from: cfg.from_address.clone().unwrap_or_else(|| "no-reply@ellkan.local".to_string()),
            tls: cfg.tls,
            username: cfg.username.clone(),
            password: crate::smtp_config::service::descifrar_password(secrets_key, cfg),
        })
    }
}

fn construir_mailer(cfg: &SmtpConfig) -> AsyncSmtpTransport<Tokio1Executor> {
    if cfg.tls {
        let mut builder = AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.host)
            .expect("host SMTP inválido")
            .port(cfg.port);
        if let (Some(u), Some(p)) = (&cfg.username, &cfg.password) {
            builder = builder.credentials(Credentials::new(u.clone(), p.clone()));
        }
        builder.build()
    } else {
        // `builder_dangerous`: sin TLS/auth, sólo para un relay local de
        // confianza (Mailhog de dev/test) — nunca el default implícito, el
        // admin tiene que tildar `tls` a propósito en `PUT /admin/smtp-config`
        // para el camino cifrado (Parte A).
        AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.host).port(cfg.port).build()
    }
}

async fn enviar(mailer: &AsyncSmtpTransport<Tokio1Executor>, from: &str, correo: &EmailPendiente) -> anyhow::Result<()> {
    let mensaje = Message::builder()
        .from(from.parse::<Mailbox>()?)
        .to(correo.recipient.parse::<Mailbox>()?)
        .subject(&correo.subject)
        .body(correo.body.clone())?;
    mailer.send(mensaje).await?;
    Ok(())
}

/// Poller de envío — relee `smtp_config` (Parte A) en cada tick, así que un
/// cambio del admin en `PUT /admin/smtp-config` aplica en el siguiente tick
/// sin reiniciar el proceso. Configurada, manda de verdad vía SMTP; sin
/// configurar, mantiene el stub original.
pub fn spawn_poller_de_envio<E, SC>(emails: E, smtp_config: SC, secrets_key: Arc<ClaveSecreta32>, intervalo: Duration)
where
    E: OutboundEmailRepository + Send + Sync + 'static,
    SC: SmtpConfigRepository + Send + Sync + 'static,
{
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(intervalo);
        loop {
            ticker.tick().await;

            let cfg_db = match smtp_config.obtener().await {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!(error = %e, "no se pudo leer smtp_config");
                    continue;
                }
            };

            match SmtpConfig::desde_db(&cfg_db, &secrets_key) {
                Some(cfg) => {
                    let mailer = construir_mailer(&cfg);
                    let pendientes = match emails.tomar_pendientes(50).await {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::error!(error = %e, "fallo el poller de envío de emails");
                            continue;
                        }
                    };
                    for correo in pendientes {
                        match enviar(&mailer, &cfg.from, &correo).await {
                            Ok(()) => {
                                if let Err(e) = emails.marcar_enviada(correo.id).await {
                                    tracing::error!(error = %e, "no se pudo marcar el email como enviado");
                                }
                            }
                            Err(e) => {
                                tracing::error!(error = %e, email_id = %correo.id, "fallo el envío SMTP real");
                                if let Err(e) = emails.marcar_intento_fallido(correo.id).await {
                                    tracing::error!(error = %e, "no se pudo marcar el intento fallido");
                                }
                            }
                        }
                    }
                }
                None => match emails.marcar_pendientes_como_enviadas().await {
                    Ok(0) => {}
                    Ok(n) => tracing::debug!(cantidad = n, "emails marcados como enviados (stub, sin SMTP configurado)"),
                    Err(e) => tracing::error!(error = %e, "fallo el poller de envío de emails"),
                },
            }
        }
    });
}
