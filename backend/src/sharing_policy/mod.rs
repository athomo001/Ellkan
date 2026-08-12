// Autor: Athan Espinoza

//! 2026-08-13: interruptor único de organización para la visibilidad de
//! compartir acotada por grupo (0037) — `restrict_visibility_by_group =
//! false` vuelve al comportamiento "cualquiera ve a cualquiera" de antes.
//! La excepción granular (grupo por grupo, `groups.share_exempt`) vive en
//! `groups::service`/`groups::repository`, no acá — esto es sólo el
//! apagador general.

pub mod dto;
pub mod handlers;
pub mod models;
pub mod repository;
pub mod service;
