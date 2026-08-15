// Autor: Athan Espinoza

//! F-14/F-34: políticas de MFA a nivel organización, con vínculo
//! criptográfico MFA↔sesión (hash de sesión, nunca en claro) y rate limiting
//! dedicado sobre el verificador de código. Sólo TOTP tiene un verificador
//! real hoy — `webauthn` como segundo factor queda declarado en el modelo
//! de datos pero explícitamente rechazado al configurar la política.

pub mod dto;
pub mod handlers;
pub mod models;
pub mod repository;
pub mod service;
