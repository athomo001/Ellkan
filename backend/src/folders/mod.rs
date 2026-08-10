// Autor: Athan Espinoza

//! F-09: carpetas con vista por-usuario. F-11 (2026-08-10) le agregó
//! permisos tipo Passbolt (`permissions.subject_type = 'folder'`, ya
//! soportado por el schema desde Fase 1.1 pero sin usar hasta ahora) y la
//! capacidad de mover un RECURSO a una carpeta (antes sólo se podían mover
//! carpetas entre sí) — ver `service.rs` para el detalle de qué operación
//! exige qué nivel de permiso.

pub mod dto;
pub mod handlers;
pub mod models;
pub mod repository;
pub mod service;
