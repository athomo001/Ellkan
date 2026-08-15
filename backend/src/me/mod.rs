// Autor: Athan Espinoza

//! `GET/PUT /me/preferences` (F-30/F-31/F-39) — no estaba implementado
//! todavía pese a que `users.locale/theme/clipboard_clear_minutes/
//! auto_lock_minutes` existen desde la migración `0001_fase0_core.sql`:
//! faltaba la superficie REST. Documentado igual que otros endpoints
//! agregados sobre la marcha en fases anteriores (`key-material`,
//! `rekey-metadata`) — acá el motivo es que 1.4 (frontend) recién ahora es
//! el primer consumidor real.

pub mod dto;
pub mod handlers;
pub mod models;
pub mod repository;
pub mod service;
