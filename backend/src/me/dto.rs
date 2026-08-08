// Autor: Athan Espinoza

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct PreferenciasResponse {
    pub locale: String,
    pub theme: String,
    pub clipboard_clear_minutes: i32,
    pub auto_lock_minutes: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct ActualizarPreferenciasRequest {
    pub locale: String,
    pub theme: String,
    pub clipboard_clear_minutes: i32,
    pub auto_lock_minutes: Option<i32>,
}
