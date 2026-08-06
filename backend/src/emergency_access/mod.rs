// Autor: Athan Espinoza

//! F-36: Emergency Access peer-to-peer. Complementa F-16 (admin-driven) sin
//! involucrar a la organización — el titular designa a otro usuario de
//! Ellkan como contacto de confianza, sellando el material client-side
//! contra su clave pública, mismo criterio que compartir un recurso.

pub mod dto;
pub mod handlers;
pub mod job;
pub mod models;
pub mod repository;
pub mod service;
