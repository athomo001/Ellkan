// Autor: Athan Espinoza

//! Convención `*_FILE` para secretos de despliegue. La variable de entorno
//! lleva la *ruta* al secreto, nunca el valor; el binario falla al arrancar
//! si no resuelve a un archivo legible, en vez de degradar a un default
//! inseguro.

use std::env;
use std::fs;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ellkan_crypto::secretos::ClaveSecreta32;
use secrecy::SecretBox;

pub struct Config {
    pub database_url: String,
    pub bind_addr: String,
    /// Endpoint OTLP del colector — apagado por defecto (`None`), el operador
    /// lo activa con su propio colector. Ellkan nunca "llama a casa": no hay
    /// endpoint por defecto ni telemetría enviada a nadie salvo que el propio
    /// operador lo configure.
    pub otel_endpoint: Option<String>,
    /// F-14: clave maestra de servidor para cifrar en reposo el secreto TOTP
    /// de login (`user_totp_credentials`) — primera vez que Ellkan cifra
    /// algo con una clave que el propio servidor controla, no con una clave
    /// del usuario. 32 bytes crudos, codificados en base64 en el archivo
    /// (mismo motivo que cualquier otro secreto binario de despliegue).
    pub secrets_key: ClaveSecreta32,
}

#[derive(Debug, thiserror::Error)]
pub enum ErrorConfig {
    #[error("falta la variable de entorno {0} (o {0}_FILE apuntando a un archivo legible)")]
    Faltante(&'static str),
    #[error("no se pudo leer el archivo de {0}_FILE: {1}")]
    ArchivoIllegible(&'static str, std::io::Error),
    #[error("{0} debe ser base64 de exactamente 32 bytes")]
    ClaveInvalida(&'static str),
}

fn resolver_secreto(nombre: &'static str) -> Result<String, ErrorConfig> {
    let var_file = format!("{nombre}_FILE");
    if let Ok(ruta) = env::var(&var_file) {
        return fs::read_to_string(&ruta)
            .map(|s| s.trim().to_string())
            .map_err(|e| ErrorConfig::ArchivoIllegible(nombre, e));
    }
    env::var(nombre).map_err(|_| ErrorConfig::Faltante(nombre))
}

impl Config {
    pub fn desde_entorno() -> Result<Self, ErrorConfig> {
        let secrets_key_b64 = resolver_secreto("ELLKAN_SECRETS_KEY")?;
        let bytes = B64
            .decode(secrets_key_b64.trim())
            .map_err(|_| ErrorConfig::ClaveInvalida("ELLKAN_SECRETS_KEY"))?;
        let bytes: [u8; 32] =
            bytes.try_into().map_err(|_| ErrorConfig::ClaveInvalida("ELLKAN_SECRETS_KEY"))?;

        Ok(Self {
            database_url: resolver_secreto("DATABASE_URL")?,
            bind_addr: env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string()),
            otel_endpoint: env::var("ELLKAN_OTEL_ENDPOINT").ok(),
            secrets_key: SecretBox::new(Box::new(bytes)),
        })
    }
}
