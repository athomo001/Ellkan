// Autor: Athan Espinoza

//! F-27 (política de export/import personal + `POST /export-events`) y
//! F-29 (exportación masiva de usuarios/grupos, sólo admin) — agrupados en
//! un módulo porque comparten el mismo tema ("sacar datos de Ellkan hacia
//! un archivo"), aunque F-27 gobierna datos del propio usuario (recursos,
//! generados 100% client-side, ver `spec/01-requisitos-funcionales.md`) y
//! F-29 es una proyección administrativa de lectura sin dato cifrado de
//! usuario (`spec/02-modelo-de-datos.md` §5bis: ninguno de los dos tiene
//! tabla propia salvo `export_policy`).
//!
//! **Diseño de la aplicación del server-side gate de F-27, no obvio**: no
//! existe (ni la spec pide) un endpoint nuevo que sirva el contenido a
//! exportar — eso sigue siendo `GET /resources`/`GET /resources/{id}/secret`
//! ya existentes, sin restricción propia (leer tus propios recursos nunca
//! estuvo gateado). El único punto de contacto nuevo específico de "estoy
//! exportando/importando" es `POST /export-events`, así que ahí es donde
//! vive el enforcement real: el cliente lo llama *antes* de generar el
//! archivo, y sólo si el server lo acepta (política habilitada + formato
//! permitido) procede a armar el KDBX/CSV/CXF. Si el server lo rechaza, no
//! se registra nada — no pasó ninguna exportación real.

pub mod dto;
pub mod handlers;
pub mod models;
pub mod repository;
pub mod service;
