// Autor: Athan Espinoza

//! F-37: Trusted Device / Login with Device. El servidor nunca sella ni
//! desella ninguna clave acá — sólo autoriza y mueve bytes opacos entre
//! dispositivos del mismo usuario. La rama de aprobación por admin queda
//! con su política lista pero sin mecanismo real: un admin nunca tiene la
//! clave privada del usuario en claro, así que no puede resellarla — eso
//! exige escrow de Account Recovery (F-16, Fase 1.3), todavía no construido.

pub mod dto;
pub mod handlers;
pub mod models;
pub mod repository;
pub mod service;
