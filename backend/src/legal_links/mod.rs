// Autor: Athan Espinoza

//! Pendiente #57: direcciones de la política de privacidad y de los términos
//! de la instancia. Ellkan no redacta ni guarda esos textos: el operador los
//! publica donde quiera (hay una plantilla en `manual/plantilla-privacidad.md`)
//! y carga los links en `PUT /admin/legal-links`. `GET /auth/setup-status`
//! los expone sin sesión, para el registro y el login.

pub mod handlers;
pub mod models;
pub mod repository;
pub mod service;
