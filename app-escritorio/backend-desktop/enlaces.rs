// Autor: Athan Espinoza

//! Enlaces `ellkan://` (deep links): el sistema le pasa la URL a la app
//! (a la instancia ya abierta, por ser de instancia única) y la app navega a
//! la pantalla que corresponde.
//!
//! La URL viene de afuera (un navegador, un documento, otra app), así que es
//! entrada NO confiable: sólo se aceptan las formas de abajo, con el id
//! validado, y el resultado es únicamente una ruta interna de la propia app.
//! Un enlace nunca ejecuta nada ni revela nada por sí mismo: si la bóveda
//! está bloqueada, primero hay que desbloquearla.
//!
//! Formas aceptadas (el esquema no distingue mayúsculas):
//! - `ellkan://abrir`, `ellkan://boveda`, `ellkan://vault` → `/vault`
//! - `ellkan://item/<uuid>`, `ellkan://recurso/<uuid>` → `/vault?abrir=<uuid>`

pub const ESQUEMA: &str = "ellkan";

/// ¿`argumento` de la línea de comandos es un enlace `ellkan://…`?
pub fn parece_enlace(argumento: &str) -> bool {
    argumento.len() > ESQUEMA.len() + 3
        && argumento[..ESQUEMA.len() + 3].eq_ignore_ascii_case(&format!("{ESQUEMA}://"))
}

fn es_uuid(texto: &str) -> bool {
    texto.len() == 36
        && texto.char_indices().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// Ruta interna de la app a la que lleva `url`, `None` si no es una forma
/// aceptada.
pub fn interpretar(url: &str) -> Option<String> {
    if !parece_enlace(url) {
        return None;
    }
    let resto = url[ESQUEMA.len() + 3..].trim_end_matches('/');
    let mut partes = resto.split('/');
    let accion = partes.next()?.to_ascii_lowercase();
    match (accion.as_str(), partes.next(), partes.next()) {
        ("abrir" | "boveda" | "vault", None, None) => Some("/vault".to_string()),
        ("item" | "recurso", Some(id), None) if es_uuid(id) => Some(format!("/vault?abrir={}", id.to_ascii_lowercase())),
        _ => None,
    }
}
