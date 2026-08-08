// Autor: Athan Espinoza

//! F-26: External Secure Share — único módulo de toda la API con un
//! endpoint sin sesión (`GET /{id}`). El servidor nunca ve la clave de
//! descifrado (viaja en el fragmento de la URL, que el navegador no envía);
//! acá sólo se mueven bytes opacos. Ver `spec/04-seguridad-y-amenazas.md`
//! §3bis para la excepción deliberada y acotada al modelo zero-knowledge
//! que esto representa.

pub mod dto;
pub mod handlers;
pub mod job;
pub mod models;
pub mod repository;
pub mod service;
