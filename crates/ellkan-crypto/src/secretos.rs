// Autor: Athan Espinoza

//! Redacción de secretos en memoria — `secrecy::SecretBox<T>` redacta
//! `Debug`/`Display` por construcción y hace zeroize del valor interno al
//! salir de scope.

use secrecy::SecretBox;

/// Passphrase en claro, sólo mientras se deriva la clave — nunca se persiste así.
pub type PassphraseSecreta = SecretBox<String>;

/// Clave simétrica de 32 bytes ya descifrada (clave maestra, subclave, DEK).
pub type ClaveSecreta32 = SecretBox<[u8; 32]>;
