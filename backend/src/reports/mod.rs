// Autor: Athan Espinoza

//! F-23: reportes operativos — sólo metadata operativa (fechas, estados,
//! conteos), nunca contenido cifrado ni su metadata. `GET
//! /admin/reports/{reportId}`, `reportId` como enum cerrado — un valor
//! fuera de él es `404`, nunca un reporte vacío (criterio de aceptación
//! literal de la spec).

pub mod dto;
pub mod handlers;
pub mod models;
pub mod repository;
pub mod service;
