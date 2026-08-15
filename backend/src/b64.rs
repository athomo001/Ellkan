// Autor: Athan Espinoza

//! Helper de (de)codificación base64 para los blobs opacos que cruzan la API
//! — el servidor nunca interpreta estos bytes, sólo los mueve.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

pub fn encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub fn decode(valor: &str) -> Result<Vec<u8>, base64::DecodeError> {
    STANDARD.decode(valor)
}
