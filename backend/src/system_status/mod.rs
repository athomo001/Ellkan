// Autor: Athan Espinoza

//! F-43: panel de autodiagnóstico admin — `GET /admin/system-status`. Sólo
//! lectura, agrega estado que un admin ya puede ver entrando a cada sección
//! una por una (SMTP, SSO, directory sync, rotación de clave de metadata),
//! más un par de chequeos nuevos de bajo riesgo (ping de DB, migraciones
//! aplicadas, backlog de correo saliente). No repite F-41 (`healthcheck`/
//! `datacheck` de la CLI se mantienen fuera de HTTP a propósito, acceso
//! directo a Postgres) — esto es la misma naturaleza que `GET /healthz` ya
//! existente: sólo lectura, sin acceso privilegiado, autenticado con
//! `AdminUser` igual que el resto del panel admin.

pub mod handlers;
pub mod models;
pub mod repository;
pub mod service;
