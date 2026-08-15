// Autor: Athan Espinoza

//! F-06 completo (metadata key compartida + TOFU) y F-33 (rotación con
//! ventana de superposición). El TOFU real (pinning del fingerprint) es
//! client-side — este módulo sólo garantiza que el fingerprint se sirve de
//! forma consistente desde `GET /metadata-keys`, que es lo único que le toca
//! al servidor en ese mecanismo.

pub mod dto;
pub mod handlers;
pub mod models;
pub mod repository;
pub mod rotacion;
pub mod service;
