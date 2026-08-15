// Autor: Athan Espinoza

//! Configuración SMTP editable desde el admin (`PUT /admin/smtp-config`),
//! guardada en la base de datos — reemplaza el `ELLKAN_SMTP_*` leído por
//! variable de entorno una sola vez al arrancar. Decisión explícita del
//! usuario: quiere poder configurar SMTP en caliente, sin reiniciar el
//! proceso. La contraseña se cifra en reposo con la misma clave maestra de
//! servidor que F-14 ya usa para el secreto TOTP (`AppState.secrets_key`,
//! AEAD) — nunca texto plano en la DB.
//!
//! `esta_configurado()` (`models::SmtpConfig`) es lo que F-02
//! (`auth::service::verify_con_usuario`) consulta en cada intento de login
//! para decidir si pedir verificación de dispositivo por email tiene
//! sentido — sin SMTP configurado, pedir un código que nunca va a llegar
//! bloquearía a cualquier usuario, incluido el primer admin.

pub mod dto;
pub mod handlers;
pub mod models;
pub mod repository;
pub mod service;
