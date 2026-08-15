// Autor: Athan Espinoza

//! F-40 (segundo y tercer checkbox): borrado atómico/selectivo de usuario
//! (dry-run obligatorio + transferencia todo-o-nada) y desactivación
//! (invalida sesiones activas de inmediato, rotando `security_stamp`).

pub mod dto;
pub mod handlers;
pub mod models;
pub mod repository;
pub mod service;
