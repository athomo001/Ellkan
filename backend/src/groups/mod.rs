// Autor: Athan Espinoza

//! F-12: grupos jerárquicos, managers por-grupo, subgrupos delegables. Cero
//! herencia de acceso entre padre e hijo — el árbol es sólo estructura
//! organizativa y alcance de administración delegada, nunca un mecanismo de
//! compartir (eso sigue siendo `permissions`, explícito por grupo).

pub mod dto;
pub mod handlers;
pub mod models;
pub mod repository;
pub mod service;
