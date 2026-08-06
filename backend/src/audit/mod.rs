// Autor: Athan Espinoza

//! F-13: audit log append-only de eventos de seguridad relevantes
//! (autenticación, cambios de autorización, ciclo de vida de recursos
//! compartidos, configuración organizacional) — nunca contenido descifrado
//! ni secretos, sólo qué pasó y sobre qué objeto.

pub mod consumidor;
pub mod dto;
pub mod handlers;
pub mod models;
pub mod repository;
pub mod service;
