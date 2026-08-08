// Autor: Athan Espinoza

use uuid::Uuid;

use ellkan_crypto::aead::{self, Envoltura};
use ellkan_crypto::secretos::ClaveSecreta32;

use crate::audit::models::{AuditEventType, EventoAuditoria};
use crate::error::DomainError;
use crate::eventos::{DomainEvent, EmisorDeEventos};

use super::models::SmtpConfig;
use super::repository::SmtpConfigRepository;

/// AAD fijo — a diferencia del TOTP de F-14 (AAD = `user_id`, un secreto
/// distinto por usuario), esto es un singleton de organización, no hay un id
/// variable al que atarlo.
const AAD_SMTP_PASSWORD: &[u8] = b"smtp_config.password";

pub struct SmtpConfigService<'a, R> {
    pub repo: &'a R,
    pub secrets_key: &'a ClaveSecreta32,
    pub eventos: EmisorDeEventos,
}

impl<'a, R> SmtpConfigService<'a, R>
where
    R: SmtpConfigRepository,
{
    pub async fn obtener(&self) -> Result<SmtpConfig, DomainError> {
        Ok(self.repo.obtener().await?)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn actualizar(
        &self,
        actor_id: Uuid,
        host: String,
        port: i32,
        from_address: String,
        tls: bool,
        username: Option<String>,
        password: Option<String>,
    ) -> Result<SmtpConfig, DomainError> {
        if host.trim().is_empty() {
            return Err(DomainError::ValidacionInvalida("host no puede estar vacío".into()));
        }
        if !(1..=65535).contains(&port) {
            return Err(DomainError::ValidacionInvalida("port debe estar entre 1 y 65535".into()));
        }

        let actual = self.repo.obtener().await?;
        let (password_ciphertext, password_nonce) = match password.as_deref() {
            None => (actual.password_ciphertext, actual.password_nonce),
            Some("") => (None, None),
            Some(p) => {
                // XChaCha20-Poly1305 cifrando (no descifrando) no falla —
                // mismo criterio que `mfa::service::iniciar_setup_totp`.
                let envoltura = aead::cifrar(self.secrets_key, p.as_bytes(), AAD_SMTP_PASSWORD)
                    .expect("cifrar con XChaCha20-Poly1305 no falla");
                (Some(envoltura.ciphertext), Some(envoltura.nonce.to_vec()))
            }
        };

        let nueva = SmtpConfig {
            host: Some(host),
            port: Some(port),
            from_address: Some(from_address),
            tls,
            username,
            password_ciphertext,
            password_nonce,
        };
        self.repo.actualizar(&nueva).await?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::SmtpConfigUpdated, Some(actor_id)).con_metadata(serde_json::json!({
                "host": nueva.host,
                "port": nueva.port,
                "tls": nueva.tls,
                "password_changed": password.is_some(),
            })),
        ));

        Ok(nueva)
    }
}

/// Descifra la contraseña SMTP guardada — usado tanto por el poller de envío
/// (`notificaciones::spawn_poller_de_envio`) como potencialmente por
/// diagnóstico. Devuelve `None` si no hay contraseña guardada o si el
/// descifrado falla (logueado acá, no propagado — el poller no tiene un
/// `DomainError` al que mapear esto, y un fallo de descifrado en este punto
/// sólo puede ser un bug de escritura, nunca una entrada externa).
pub fn descifrar_password(clave: &ClaveSecreta32, cfg: &SmtpConfig) -> Option<String> {
    let ciphertext = cfg.password_ciphertext.clone()?;
    let nonce_bytes = cfg.password_nonce.clone()?;
    let nonce: [u8; 24] = match nonce_bytes.try_into() {
        Ok(n) => n,
        Err(_) => {
            tracing::error!("smtp_config.password_nonce no tiene 24 bytes — dato corrupto");
            return None;
        }
    };
    let envoltura = Envoltura { nonce, ciphertext };
    match aead::descifrar(clave, &envoltura, AAD_SMTP_PASSWORD) {
        Ok(bytes) => String::from_utf8(bytes).ok(),
        Err(_) => {
            tracing::error!("no se pudo descifrar smtp_config.password_ciphertext");
            None
        }
    }
}
