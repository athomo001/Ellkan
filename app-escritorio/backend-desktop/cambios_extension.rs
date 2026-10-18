// Autor: Athan Espinoza

//! Cambios que hace la extensión de navegador en la bóveda local, avisados a
//! la interfaz de la app para que los suba al servidor vinculado.
//!
//! La subida al servidor la hace la interfaz (`frontend/src/lib/sync/
//! notificador.ts`), pero la extensión le habla directo a este backend: sin
//! este aviso, una contraseña cambiada desde la extensión quedaba sólo en la
//! app (bug real 2026-10-18). Cubre los dos caminos de la extensión:
//!
//! - native messaging (`src-tauri/src/canal_extension.rs`, sólo Windows), que
//!   llama a [`avisar`] con la respuesta ya armada;
//! - el puerto TCP de respaldo (y el único en Linux), vía el middleware
//!   [`middleware_tcp`], que reconoce a la extensión por su `Origin`.
//!
//! Lo que pide la propia ventana de la app (`Origin` de Tauri) no pasa por
//! acá: esa ya avisa al servidor por su cuenta.

use std::sync::OnceLock;

use axum::body::Body;
use axum::extract::Request;
use axum::http::header;
use axum::middleware::Next;
use axum::response::Response;

/// Lo que hace la app con el aviso: `(id del recurso, "subir" | "borrar")`.
pub type Aviso = fn(&str, &str);

static AVISO: OnceLock<Aviso> = OnceLock::new();

/// Lo fija la app al arrancar (`src-tauri/src/lib.rs`). Sin él (tests, o
/// antes de que la ventana exista) los cambios sólo se registran en el log.
pub fn al_cambiar(aviso: Aviso) {
    let _ = AVISO.set(aviso);
}

/// Respuestas más grandes que esto no se leen para buscar el id (crear
/// devuelve un recurso, unos pocos KB).
const MAX_CUERPO: usize = 1024 * 1024;

/// `Some((id, operación))` si el pedido cambió un recurso de la bóveda.
/// `POST /resources` (crear) trae el id en la respuesta; el resto, en la ruta.
pub fn detectar(metodo: &str, ruta: &str, status: u16, cuerpo_respuesta: &[u8]) -> Option<(String, &'static str)> {
    if !(200..300).contains(&status) || !matches!(metodo, "POST" | "PUT" | "DELETE") {
        return None;
    }
    let ruta = ruta.split('?').next().unwrap_or(ruta);
    let resto = ruta.strip_prefix("/resources")?;
    let id = match resto.strip_prefix('/').and_then(|r| r.split('/').next()) {
        Some(seg) => seg.to_string(),
        None if resto.is_empty() => serde_json::from_slice::<serde_json::Value>(cuerpo_respuesta)
            .ok()?
            .get("id")?
            .as_str()?
            .to_string(),
        None => return None,
    };
    if !es_uuid(&id) {
        return None;
    }
    let es_borrado = metodo == "DELETE" && resto.trim_start_matches('/').split('/').count() == 1;
    Some((id, if es_borrado { "borrar" } else { "subir" }))
}

/// Detecta, registra en `Ellkan.log` y avisa a la app.
pub fn avisar(metodo: &str, ruta: &str, status: u16, cuerpo_respuesta: &[u8]) {
    let Some((id, operacion)) = detectar(metodo, ruta, status, cuerpo_respuesta) else { return };
    tracing::info!("extensión: {operacion} {id} → se avisa a la app para subirlo al servidor");
    if let Some(aviso) = AVISO.get() {
        aviso(&id, operacion);
    }
}

/// `Origin` de una extensión de navegador (mismos esquemas que acepta
/// `origen::origen_permitido`).
fn es_origen_de_extension(origen: &str) -> bool {
    ["chrome-extension://", "moz-extension://", "safari-web-extension://"]
        .iter()
        .any(|e| origen.starts_with(e))
}

/// Middleware del router local: avisa los cambios que la extensión hace por
/// el puerto TCP.
pub async fn middleware_tcp(req: Request, next: Next) -> Response {
    let de_extension = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|o| o.to_str().ok())
        .is_some_and(es_origen_de_extension);
    let metodo = req.method().as_str().to_string();
    let ruta = req.uri().path().to_string();
    if !de_extension || !matches!(metodo.as_str(), "POST" | "PUT" | "DELETE") || !ruta.starts_with("/resources") {
        return next.run(req).await;
    }

    let respuesta = next.run(req).await;
    let status = respuesta.status().as_u16();
    // Sólo crear necesita leer el cuerpo (para sacar el id).
    if ruta != "/resources" {
        avisar(&metodo, &ruta, status, &[]);
        return respuesta;
    }
    let (partes, cuerpo) = respuesta.into_parts();
    match axum::body::to_bytes(cuerpo, MAX_CUERPO).await {
        Ok(bytes) => {
            avisar(&metodo, &ruta, status, &bytes);
            Response::from_parts(partes, Body::from(bytes))
        }
        Err(_) => Response::from_parts(partes, Body::empty()),
    }
}

/// `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` en hex: a la interfaz llega siempre
/// un id de recurso válido, nunca un trozo arbitrario de la ruta.
fn es_uuid(s: &str) -> bool {
    s.len() == 36 && s.char_indices().all(|(i, c)| if matches!(i, 8 | 13 | 18 | 23) { c == '-' } else { c.is_ascii_hexdigit() })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "cbae7709-dd22-46fa-a8d5-e0dfa1e2a975";

    #[test]
    fn editar_y_borrar_salen_de_la_ruta() {
        assert_eq!(detectar("PUT", &format!("/resources/{ID}"), 200, b""), Some((ID.into(), "subir")));
        assert_eq!(detectar("DELETE", &format!("/resources/{ID}"), 204, b""), Some((ID.into(), "borrar")));
        // Mover o quitar un tag cambia el recurso, no lo borra.
        assert_eq!(detectar("PUT", &format!("/resources/{ID}/move"), 200, b""), Some((ID.into(), "subir")));
        assert_eq!(detectar("DELETE", &format!("/resources/{ID}/tags/x"), 204, b""), Some((ID.into(), "subir")));
    }

    #[test]
    fn crear_saca_el_id_de_la_respuesta() {
        let cuerpo = format!(r#"{{"id":"{ID}","resource_type_slug":"login-password"}}"#);
        assert_eq!(detectar("POST", "/resources", 200, cuerpo.as_bytes()), Some((ID.into(), "subir")));
    }

    #[test]
    fn ignora_lecturas_errores_y_ids_raros() {
        assert_eq!(detectar("GET", &format!("/resources/{ID}"), 200, b""), None);
        assert_eq!(detectar("PUT", &format!("/resources/{ID}"), 409, b""), None);
        assert_eq!(detectar("PUT", "/resources/../../etc", 200, b""), None);
        assert_eq!(detectar("POST", "/resources", 200, b"no json"), None);
        assert_eq!(detectar("POST", "/folders", 200, b""), None);
    }
}
