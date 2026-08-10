// Autor: Athan Espinoza

//! F-24: política de auto-registro público — habilitado/deshabilitado y
//! allowlist de dominios de email. La verificación de email en sí (código
//! de un solo uso) y el gate de SMTP-configurado viven en `auth::service`
//! (dependen de si el registro es el bootstrap de la instancia, algo que
//! este módulo no necesita saber) — acá sólo se administra y se consulta la
//! allowlist.

pub mod dto;
pub mod handlers;
pub mod models;
pub mod repository;
pub mod service;
