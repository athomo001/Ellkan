// Autor: Athan Espinoza

//! Segunda implementación (SQLite, modo escritorio) de `SmtpConfigRepository`
//! — sin tabla: en modo escritorio no hay SMTP que configurar (no hay
//! `outbound_emails`/poller compilado, spec/13 §3), así que `obtener()`
//! devuelve siempre "no configurado" en memoria. Esto es lo que
//! `auth::service::verify_con_usuario` ya consulta para decidir si F-02
//! (verificación de dispositivo por email) tiene sentido — con `host: None`
//! siempre toma el camino "sin SMTP, marcar conocido sin pedir nada" que ya
//! existe hoy para el servidor sin SMTP configurado, sin código nuevo.

use crate::error::RepoError;

use crate::smtp_config::models::SmtpConfig;
use crate::smtp_config::repository::SmtpConfigRepository;

#[derive(Clone, Default)]
pub struct SqliteSmtpConfigRepository;

impl SmtpConfigRepository for SqliteSmtpConfigRepository {
    async fn obtener(&self) -> Result<SmtpConfig, RepoError> {
        Ok(SmtpConfig {
            host: None,
            port: None,
            from_address: None,
            tls: false,
            username: None,
            password_ciphertext: None,
            password_nonce: None,
        })
    }

    async fn actualizar(&self, _config: &SmtpConfig) -> Result<(), RepoError> {
        Ok(())
    }
}
