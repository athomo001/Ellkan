// Autor: Athan Espinoza

//! Pendiente #89 (F-43): aviso de versión nueva. **Opcional y apagado por
//! defecto** (decisión del usuario, 2026-11-22): es la única conexión a
//! internet que Ellkan haría por su cuenta. Con el aviso activo, el servidor
//! consulta una vez al día la última Release pública en GitHub
//! (`ELLKAN_UPDATE_CHECK_URL`, por defecto la API de Releases del repo) y
//! guarda sólo el número y el link; el panel de estado del sistema se lo
//! muestra a los admins. No manda nada de la instancia: un `GET` anónimo con
//! un `User-Agent` genérico.

pub mod handlers;
pub mod job;
pub mod models;
pub mod repository;
pub mod service;
