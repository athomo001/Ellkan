// Autor: Athan Espinoza

//! F-17: SSO OIDC. `authorization_code` + PKCE obligatorio, vinculación de
//! cuenta explícita (nunca por email sin `email_verified`), JIT
//! provisioning apagado por default. SAML pospuesto a Fase 2+.

pub mod dto;
pub mod handlers;
pub mod models;
pub mod repository;
pub mod service;
