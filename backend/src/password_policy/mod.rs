// Autor: Athan Espinoza

//! F-15: políticas de password/passphrase organizacionales. La regla en sí
//! (longitud/entropía mínima de una passphrase concreta) se valida
//! client-side con `zxcvbn` — la passphrase nunca viaja al servidor para
//! que éste la valide — así que este módulo sólo administra los parámetros
//! de la política y las reglas del generador de contraseñas de recursos.

pub mod dto;
pub mod handlers;
pub mod models;
pub mod repository;
pub mod service;
