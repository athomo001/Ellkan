// Autor: Athan Espinoza

//! Convención `*_FILE` para secretos de despliegue. La variable de entorno
//! lleva la *ruta* al secreto, nunca el valor; el binario falla al arrancar
//! si no resuelve a un archivo legible, en vez de degradar a un default
//! inseguro.

use std::env;
use std::fs;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
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
    /// Operativa 1 (spec/11): TLS terminado por el propio binario vía
    /// `axum-server`+`rustls`, alternativa liviana a levantar un reverse
    /// proxy aparte sólo para eso — un cert/key PEM ya son naturalmente
    /// archivos, así que estas dos variables son la ruta directa, sin el
    /// nivel extra de indirección `_FILE` que sí aplica a secretos cuyo
    /// valor normalmente viaja por variable de entorno. Ambas ausentes
    /// (default) mantiene el comportamiento de siempre: HTTP plano, TLS
    /// delegado a lo que el operador ponga adelante, si pone algo.
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ErrorConfig {
    /// QA-26: lista de proxies confiables ilegible — mejor no arrancar que
    /// arrancar ignorándola (todos compartiendo un mismo límite).
    #[error("{0}")]
    ProxiesConfiables(String),
    #[error("falta la variable de entorno {0} (o {0}_FILE apuntando a un archivo legible)")]
    Faltante(&'static str),
    #[error("no se pudo leer el archivo de {0}_FILE: {1}")]
    ArchivoIllegible(&'static str, std::io::Error),
    #[error("{0} debe ser base64 de exactamente 32 bytes")]
    ClaveInvalida(&'static str),
    #[error("ELLKAN_TLS_CERT_FILE y ELLKAN_TLS_KEY_FILE tienen que estar las dos o ninguna, no sólo una")]
    TlsIncompleto,
    #[error("ELLKAN_SETUP_TOKEN debe tener al menos {0} caracteres")]
    TokenDeInstalacionCorto(usize),
    #[error(
        "falta {0}: es la dirección con la que se entra a Ellkan (passkeys y links de los emails). Ejemplo: ELLKAN_RP_ID=ellkan.tuempresa.com y ELLKAN_RP_ORIGIN=https://ellkan.tuempresa.com (en local, localhost y http://localhost:8080)"
    )]
    DireccionPublicaFaltante(&'static str),
}

/// Largo mínimo del token de instalación: es una credencial que da el rol
/// de admin, no puede ser adivinable.
const SETUP_TOKEN_LARGO_MINIMO: usize = 24;

/// QA-11: token de instalación opcional (`ELLKAN_SETUP_TOKEN` o
/// `ELLKAN_SETUP_TOKEN_FILE`). Si está configurado, el primer registro de
/// una instancia vacía (el que nace admin) tiene que presentarlo; si no,
/// se mantiene el comportamiento histórico (el primer registro nace admin).
pub fn token_de_instalacion() -> Result<Option<SecretBox<String>>, ErrorConfig> {
    let valor = match resolver_secreto("ELLKAN_SETUP_TOKEN") {
        Ok(v) => v,
        Err(ErrorConfig::Faltante(_)) => return Ok(None),
        Err(e) => return Err(e),
    };
    if valor.chars().count() < SETUP_TOKEN_LARGO_MINIMO {
        return Err(ErrorConfig::TokenDeInstalacionCorto(SETUP_TOKEN_LARGO_MINIMO));
    }
    Ok(Some(SecretBox::new(Box::new(valor))))
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
        let bytes = B64.decode(secrets_key_b64.trim()).map_err(|_| ErrorConfig::ClaveInvalida("ELLKAN_SECRETS_KEY"))?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| ErrorConfig::ClaveInvalida("ELLKAN_SECRETS_KEY"))?;

        let tls_cert_path = env::var("ELLKAN_TLS_CERT_FILE").ok();
        let tls_key_path = env::var("ELLKAN_TLS_KEY_FILE").ok();
        if tls_cert_path.is_some() != tls_key_path.is_some() {
            return Err(ErrorConfig::TlsIncompleto);
        }

        // QA-30 (pendiente #115): sin estas dos, WebAuthn y los links de
        // recuperación quedaban apuntando a `localhost` sin ningún aviso. El
        // servidor no arranca sin ellas (el `docker-compose.yml` las define,
        // con `localhost` para la instalación local). `state.rs` conserva el
        // default sólo para tests y la app de escritorio, que no pasan por acá.
        for variable in ["ELLKAN_RP_ID", "ELLKAN_RP_ORIGIN"] {
            if env::var(variable).map(|v| v.trim().is_empty()).unwrap_or(true) {
                return Err(ErrorConfig::DireccionPublicaFaltante(variable));
            }
        }

        crate::ip_cliente::ProxiesConfiables::desde_entorno().map_err(ErrorConfig::ProxiesConfiables)?;

        Ok(Self {
            database_url: resolver_secreto("DATABASE_URL")?,
            bind_addr: env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string()),
            otel_endpoint: env::var("ELLKAN_OTEL_ENDPOINT").ok(),
            secrets_key: SecretBox::new(Box::new(bytes)),
            tls_cert_path,
            tls_key_path,
        })
    }
}
