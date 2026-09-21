// Autor: Athan Espinoza

//! F-47 (spec/13 §7): `GET /sync?since=<cursor>` — el endpoint que la app de
//! escritorio usa cuando una bóveda está en "modo conectado" contra ESTE
//! servidor (Postgres/equipo). No tiene nada que ver con el backend local
//! SQLite del modo escritorio: ese nunca sirve `/sync`, sólo lo CONSUME como
//! cliente REST (spec/12 §6bis) — este módulo vive enteramente del lado
//! servidor.
//!
//! Cubre `resources`+`secret_envelopes`, `folders`+`folder_items` y `tags`
//! — no `resource_tags` (aplicar/quitar un tag no toca ningún timestamp
//! hoy, gap documentado en `handlers.rs`, aceptado en la primera versión).

pub mod dto;
pub mod handlers;
