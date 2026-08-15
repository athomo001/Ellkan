// Autor: Athan Espinoza

//! F-16: Account Recovery con escrow opt-in y aprobación por umbral. El
//! usuario sella su clave privada contra la clave pública de recuperación
//! organizacional client-side; el servidor sólo la desella una vez que una
//! solicitud junta el umbral de admins configurado, y únicamente para
//! re-sellarla contra la clave efímera del solicitante — nunca queda en
//! claro más que el instante del re-sellado.

pub mod dto;
pub mod handlers;
pub mod models;
pub mod repository;
pub mod service;
