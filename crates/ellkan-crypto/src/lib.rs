// Autor: Athan Espinoza

//! Núcleo criptográfico de Ellkan — compilado nativo y a `wasm32-unknown-unknown`.
//! Cero `unsafe`.

pub mod aead;
pub mod aleatoriedad;
pub mod claves;
pub mod clave_privada;
pub mod comparacion;
pub mod derivacion;
pub mod secretos;
pub mod sellado;
pub mod sesion;
pub mod totp;
