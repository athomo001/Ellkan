// Autor: Athan Espinoza

//! F-18: SCIM 2.0. Alcance documentado: sólo `/scim/v2/Users` (alta
//! idempotente por `externalId`, listado paginado, desactivar sin borrar) —
//! `/scim/v2/Groups` queda deferred, sin código todavía, porque ningún
//! criterio de aceptación de F-18 ejercita membresía de grupo vía SCIM
//! (a diferencia de Users, donde sí hay tres escenarios concretos que
//! probar). Límite real, no oculto.

pub mod dto;
pub mod extractor;
pub mod handlers;
pub mod models;
pub mod repository;
pub mod service;
