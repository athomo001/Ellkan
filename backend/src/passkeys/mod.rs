// Autor: Athan Espinoza

//! F-03: passkeys/WebAuthn como método de login alternativo. La ceremonia en
//! sí (registro/autenticación) la resuelve `webauthn-rs` — este módulo sólo
//! persiste sus tipos (opacos para nuestro código) y conecta el resultado
//! con el resto del backend (emisión de sesión). La extensión PRF es
//! enteramente client-side: el servidor sólo guarda el blob opaco que el
//! cliente decide subir, nunca calcula ni valida nada de PRF por su cuenta.

pub mod dto;
pub mod handlers;
pub mod models;
pub mod repository;
pub mod service;
