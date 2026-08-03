// Autor: Athan Espinoza

//! F-09: carpetas con vista por-usuario — capa puramente organizativa, sin
//! control de acceso propio (eso lo resuelve F-11 sobre los recursos). No
//! expone un endpoint para colocar recursos dentro de una carpeta todavía:
//! `spec/03-api-contrato.md` sólo lista `GET/POST /folders` y
//! `PUT /folders/{id}/move` para esta fase — el esquema ya soporta
//! `folder_items.resource_id` para cuando ese endpoint se agregue.

pub mod dto;
pub mod handlers;
pub mod models;
pub mod repository;
pub mod service;
