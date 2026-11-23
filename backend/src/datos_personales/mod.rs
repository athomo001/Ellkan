// Autor: Athan Espinoza

//! Pendiente #58: derecho de acceso del titular. `GET /me/personal-data`
//! devuelve, en un JSON descargable, los datos personales que el servidor
//! tiene de quien lo pide **y puede leer**: cuenta, grupos, sesiones,
//! dispositivos, passkeys, identidades SSO, contactos de emergencia y su
//! historial en la auditoría.
//!
//! Lo que no incluye, a propósito:
//! - El contenido de la bóveda: está cifrado de extremo a extremo y el
//!   servidor no puede leerlo; se exporta desde el cliente (CSV/KeePass).
//! - Claves, hashes, secretos TOTP, sobres sellados: material criptográfico,
//!   no datos sobre la persona.
//! - El `metadata` de cada entrada de auditoría: puede nombrar a otras
//!   personas (a quién se agregó a un grupo, con quién se compartió). Se da
//!   el tipo de evento, sobre qué clase de objeto y cuándo.

pub mod handlers;
pub mod models;
pub mod repository;
pub mod service;
