// Autor: Athan Espinoza

//! Núcleo criptográfico de Ellkan — compilado nativo y a `wasm32-unknown-unknown`.
//! Cero `unsafe`.

pub mod aead;
pub mod aleatoriedad;
pub mod claves;
pub mod clave_privada;
pub mod comparacion;
pub mod derivacion;
pub mod prf;
pub mod secretos;
pub mod sellado;
pub mod sesion;
pub mod totp;
// Sólo wasm32: `wasm_bindgen` es dependencia condicional para ese target
// (Cargo.toml) — este módulo es la superficie JS del frontend (Fase 1.4).
#[cfg(target_arch = "wasm32")]
pub mod wasm_api;
