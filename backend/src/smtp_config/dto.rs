// Autor: Athan Espinoza

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct SmtpConfigResponse {
    pub configurado: bool,
    pub host: Option<String>,
    pub port: Option<i32>,
    pub from_address: Option<String>,
    pub tls: bool,
    pub username: Option<String>,
    // La contraseña nunca se devuelve — write-only, mismo criterio que
    // cualquier campo de contraseña del sistema.
}

/// `password`: `null`/ausente conserva la ya guardada sin tocarla; `""` la
/// borra (para pasar a un relay sin auth, ej. Mailhog); cualquier otro
/// valor la reemplaza y se recifra.
#[derive(Debug, Deserialize)]
pub struct ActualizarSmtpConfigRequest {
    pub host: String,
    pub port: i32,
    pub from_address: String,
    pub tls: bool,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ProbarSmtpRequest {
    pub to: String,
}

/// `status`: `"enviado"` | `"fallido"` | `"pendiente"` (ver `SmtpConfigService::probar_envio`).
#[derive(Debug, Serialize)]
pub struct ProbarSmtpResponse {
    pub status: String,
}
