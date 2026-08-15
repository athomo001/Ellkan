// Autor: Athan Espinoza

//! Recovery kit: recuperación de cuenta self-service, sin admin de por
//! medio (par X25519 generado en el cliente, la privada nunca toca el
//! servidor). Modelo de confianza opuesto a `account_recovery` (F-16,
//! escrow contra la clave org + aprobación de N admins) — no lo extiende,
//! ver `spec/04-seguridad-y-amenazas.md` §6.

pub mod dto;
pub mod handlers;
pub mod models;
pub mod repository;
pub mod service;
