// Autor: Athan Espinoza

//! F-53 (#60): actualizador firmado.
//!
//! El canal es `latest.json` de la última Release estable de GitHub (las
//! `-dev` son pre-releases y `releases/latest` no las ve). El plugin descarga
//! el paquete y **verifica su firma minisign contra la clave pública de
//! `tauri.conf.json` antes de instalarlo**: un paquete sin firma, con otra
//! firma o alterado se rechaza (criterio de aceptación de F-53).
//!
//! Se expone como dos comandos propios en vez de los permisos del plugin en
//! JS: así la WebView no gana capacidades nuevas y la regla del modo portable
//! queda en el proceso nativo. En modo portable no se ofrece: el paquete es un
//! MSI que instalaría Ellkan en el sistema, no actualizaría la carpeta del ZIP.
//!
//! Antes de migrar la base, la versión nueva hace su copia de seguridad al
//! arrancar (`backend-desktop/respaldos.rs`), así que una actualización con
//! migración nunca deja la bóveda sin respaldo.

use tauri::AppHandle;
use tauri_plugin_updater::UpdaterExt;

use crate::portable;

#[derive(serde::Serialize)]
pub struct ActualizacionDisponible {
  version: String,
  version_actual: String,
  notas: Option<String>,
  fecha: Option<String>,
}

fn texto_error(e: impl std::fmt::Display) -> String {
  format!("no se pudo buscar la actualización: {e}")
}

/// `None` si la app está al día, en modo portable, o si no hay red (el
/// error de red sí se devuelve, para que Ajustes lo muestre).
#[tauri::command]
pub async fn buscar_actualizacion(app: AppHandle) -> Result<Option<ActualizacionDisponible>, String> {
  if portable::activo() {
    return Ok(None);
  }
  let actualizacion = app.updater().map_err(texto_error)?.check().await.map_err(texto_error)?;
  Ok(actualizacion.map(|u| {
    log::info!("[actualizador] disponible {} (actual {})", u.version, u.current_version);
    ActualizacionDisponible {
      version: u.version,
      version_actual: u.current_version,
      notas: u.body,
      fecha: u.date.map(|d| d.to_string()),
    }
  }))
}

/// Descarga, verifica la firma e instala; después reinicia. En Windows el
/// instalador (modo `passive`, con barra de progreso) cierra la app solo y
/// la vuelve a abrir. Si la firma no coincide, devuelve error sin instalar.
#[tauri::command]
pub async fn instalar_actualizacion(app: AppHandle) -> Result<(), String> {
  if portable::activo() {
    return Err("en modo portable la actualización se hace bajando el ZIP nuevo".into());
  }
  let Some(actualizacion) = app.updater().map_err(texto_error)?.check().await.map_err(texto_error)? else {
    return Err("ya tenés la última versión".into());
  };
  log::info!("[actualizador] instalando {}", actualizacion.version);
  actualizacion
    .download_and_install(|_, _| {}, || log::info!("[actualizador] descarga verificada"))
    .await
    .map_err(|e| {
      log::warn!("[actualizador] falló la instalación: {e}");
      format!("no se pudo instalar la actualización: {e}")
    })?;
  app.restart()
}

/// Espera antes del chequeo automático: que no compita con el arranque, el
/// sync y la reconciliación.
const ESPERA_CHEQUEO_INICIAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Chequeo automático, una vez por arranque: si hay versión nueva, el aviso
/// de la esquina lo dice y la instalación queda a un clic en Ajustes (nunca
/// se instala sin que el usuario lo pida: reinicia la app). Sin red, en
/// silencio (queda en el log). Nada en modo portable ni en desarrollo.
pub fn revisar_al_arrancar(app: AppHandle) {
  if portable::activo() || cfg!(debug_assertions) {
    return;
  }
  tauri::async_runtime::spawn(async move {
    tokio::time::sleep(ESPERA_CHEQUEO_INICIAL).await;
    match buscar_actualizacion(app.clone()).await {
      Ok(Some(_)) => crate::mostrar_aviso(&app, serde_json::json!({ "tipo": "actualizacion" })),
      Ok(None) => log::info!("[actualizador] la app está al día"),
      Err(e) => log::warn!("[actualizador] {e}"),
    }
  });
}
