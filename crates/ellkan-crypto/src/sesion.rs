// Autor: Athan Espinoza

//! Cachés de sesión en memoria. La clave privada descifrada **nunca** se
//! cachea acá — sólo DEKs simétricas por recurso (fast-path tras el primer
//! descifrado asimétrico) y la passphrase, para reconstruir la clave privada
//! bajo demanda.

use std::collections::HashMap;

use crate::secretos::{ClaveSecreta32, PassphraseSecreta};

/// Caché de DEKs simétricas por `resource_id`, descartada al logout.
#[derive(Default)]
pub struct CacheDeSessionKeys {
    claves: HashMap<String, ClaveSecreta32>,
}

impl CacheDeSessionKeys {
    pub fn nueva() -> Self {
        Self::default()
    }

    pub fn insertar(&mut self, resource_id: impl Into<String>, dek: ClaveSecreta32) {
        self.claves.insert(resource_id.into(), dek);
    }

    pub fn obtener(&self, resource_id: &str) -> Option<&ClaveSecreta32> {
        self.claves.get(resource_id)
    }

    /// Se llama al logout — descarta toda DEK cacheada.
    pub fn limpiar(&mut self) {
        self.claves.clear();
    }

    pub fn len(&self) -> usize {
        self.claves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.claves.is_empty()
    }
}

/// Caché de la passphrase durante la sesión — no confundir con cachear la
/// clave privada ya descifrada (eso nunca). La clave privada se reconstruye
/// fresca en cada operación a partir de esta passphrase + el blob cifrado.
pub struct CacheDePassphrase {
    passphrase: Option<PassphraseSecreta>,
}

impl CacheDePassphrase {
    pub fn vacia() -> Self {
        Self { passphrase: None }
    }

    pub fn establecer(&mut self, passphrase: PassphraseSecreta) {
        self.passphrase = Some(passphrase);
    }

    pub fn obtener(&self) -> Option<&PassphraseSecreta> {
        self.passphrase.as_ref()
    }

    /// Se llama al logout o al cerrar el navegador — nunca toca disco, así
    /// que basta con soltar la referencia (el `Drop` de `SecretBox` hace zeroize).
    pub fn limpiar(&mut self) {
        self.passphrase = None;
    }
}

impl Default for CacheDePassphrase {
    fn default() -> Self {
        Self::vacia()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aleatoriedad::bytes_aleatorios;
    use secrecy::{ExposeSecret, SecretBox};

    #[test]
    fn cache_de_session_keys_guarda_y_limpia() {
        let mut cache = CacheDeSessionKeys::nueva();
        let dek: ClaveSecreta32 = SecretBox::new(Box::new(bytes_aleatorios::<32>()));
        cache.insertar("resource-1", dek);
        assert!(cache.obtener("resource-1").is_some());
        assert!(cache.obtener("resource-2").is_none());
        cache.limpiar();
        assert!(cache.is_empty());
    }

    #[test]
    fn cache_de_passphrase_guarda_y_limpia() {
        let mut cache = CacheDePassphrase::vacia();
        assert!(cache.obtener().is_none());
        cache.establecer(SecretBox::new(Box::new("passphrase".to_string())));
        assert_eq!(cache.obtener().unwrap().expose_secret(), "passphrase");
        cache.limpiar();
        assert!(cache.obtener().is_none());
    }
}
