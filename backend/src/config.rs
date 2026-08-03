// Autor: Athan Espinoza

//! Convención `*_FILE` para secretos de despliegue. La variable de entorno
//! lleva la *ruta* al secreto, nunca el valor; el binario falla al arrancar
//! si no resuelve a un archivo legible, en vez de degradar a un default
//! inseguro.

use std::env;
use std::fs;

pub struct Config {
    pub database_url: String,
    pub bind_addr: String,
    /// Endpoint OTLP del colector — apagado por defecto (`None`), el operador
    /// lo activa con su propio colector. Ellkan nunca "llama a casa": no hay
    /// endpoint por defecto ni telemetría enviada a nadie salvo que el propio
    /// operador lo configure.
    pub otel_endpoint: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ErrorConfig {
    #[error("falta la variable de entorno {0} (o {0}_FILE apuntando a un archivo legible)")]
    Faltante(&'static str),
    #[error("no se pudo leer el archivo de {0}_FILE: {1}")]
    ArchivoIllegible(&'static str, std::io::Error),
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
        Ok(Self {
            database_url: resolver_secreto("DATABASE_URL")?,
            bind_addr: env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string()),
            otel_endpoint: env::var("ELLKAN_OTEL_ENDPOINT").ok(),
        })
    }
}
