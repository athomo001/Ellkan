// Autor: Athan Espinoza

//! F-40 (primer checkbox): política de retención/purga. Hard-delete físico
//! de filas soft-deleted vencidas — `audit_log_entries` tiene su propia
//! retención, independiente (`audit_log_retention_days`), nunca purgada por
//! `data_retention_days`. El borrado atómico/selectivo de un usuario
//! puntual es un checkbox aparte (`users_admin`), no pasa por acá.

pub mod dto;
pub mod handlers;
pub mod job;
pub mod models;
pub mod repository;
pub mod service;
