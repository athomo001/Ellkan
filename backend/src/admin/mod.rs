// Autor: Athan Espinoza

//! Groundwork de RBAC (F-22), adelantado sobre su fase formal (1.3) — ver
//! `spec/05-plan-de-implementacion.md` para el porqué. Hoy sólo resuelve el
//! permiso comodín `"*"` que consume el extractor `AdminUser`; permisos
//! granulares se agregan cuando 1.3 tenga un primer consumidor real.

pub mod dto;
pub mod handlers;
pub mod models;
pub mod repository;
pub mod service;
