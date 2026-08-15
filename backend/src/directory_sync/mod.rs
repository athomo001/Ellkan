// Autor: Athan Espinoza

//! F-19: Directory Sync LDAP + dry-run. Reusa el mismo mecanismo de
//! usuarios "externamente aprovisionados" que F-18 (`users.external_id`,
//! `scim::repository::ScimUserRepository`) — alcance documentado: SCIM y
//! Directory Sync comparten esa columna en este primer corte, no hay
//! soporte todavía para que ambos aprovisionen simultáneamente sin
//! pisarse (ningún caso de uso real de v1 combina los dos a la vez).

pub mod dto;
pub mod handlers;
pub mod models;
pub mod repository;
pub mod service;
