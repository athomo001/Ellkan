// Autor: Athan Espinoza

//! Segunda implementación (SQLite, modo escritorio) de los repositorios de
//! cada módulo — antes vivían como `<módulo>/repository_sqlite.rs`, uno al
//! lado de `<módulo>/repository.rs` (Postgres). Movidos acá el 2026-09-16 a
//! pedido explícito del usuario: quería el código propio del modo escritorio
//! junto, no repartido módulo por módulo — todo lo que compila sólo bajo
//! `--features desktop` vive ahora bajo `app-escritorio/backend-desktop/`
//! (fuera de `backend/src/` del todo, vía `#[path]` en `backend/src/lib.rs`),
//! sin excepción (este módulo entero ya está `#[cfg(feature = "desktop")]`
//! en `lib.rs`, así que ningún archivo de acá necesita su propio `#[cfg]`).
//! Cada archivo implementa los traits `Repository` que YA existían en
//! `<módulo>::repository` — no se tocó ningún trait ni la versión Postgres
//! al mover esto.

pub mod admin;
pub mod auth;
pub mod folders;
pub mod groups;
pub mod mfa;
pub mod recovery_kit;
pub mod resources;
pub mod self_registration;
pub mod smtp_config;
pub mod tags;
