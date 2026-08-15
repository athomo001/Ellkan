// Autor: Athan Espinoza

//! F-10: tags personales y compartidos. Un tag personal sólo lo ve/edita su
//! `created_by`; uno compartido lo puede aplicar cualquiera con `update`+
//! sobre el recurso, pero sólo un admin puede crearlo/renombrarlo.

pub mod dto;
pub mod handlers;
pub mod models;
pub mod repository;
pub mod service;
