// Autor: Athan Espinoza

//! CSPRNG explícito — nunca `thread_rng()` para material que protege un secreto.

use rand_core::{CryptoRng, TryRng, UnwrapErr};

/// RNG criptográfico (generación rand_core 0.10: x25519-dalek, ed25519-dalek,
/// chacha20poly1305). `getrandom::SysRng` es falible por diseño (la entropía del
/// SO puede fallar); `UnwrapErr` lo adapta a la interfaz infalible que exigen
/// `StaticSecret::random_from_rng`/`SigningKey::generate`, haciendo panic si el
/// SO no puede entregar entropía — nunca degradar a un generador no criptográfico.
pub fn csprng() -> impl CryptoRng {
    UnwrapErr(getrandom::SysRng)
}

/// RNG criptográfico en la generación rand_core 0.6, sólo para `crypto_box`
/// (ver comentario en `Cargo.toml` sobre por qué coexisten dos generaciones).
pub fn csprng_v6() -> rand_core_06::OsRng {
    rand_core_06::OsRng
}

/// Genera bytes criptográficamente aleatorios — nonces de AEAD, salts de Argon2id.
pub fn bytes_aleatorios<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::SysRng
        .try_fill_bytes(&mut buf)
        .expect("el SO debe poder entregar entropía criptográfica");
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_aleatorios_no_son_todos_cero() {
        let a: [u8; 32] = bytes_aleatorios();
        let b: [u8; 32] = bytes_aleatorios();
        assert_ne!(a, [0u8; 32]);
        assert_ne!(a, b, "dos llamadas no deberían coincidir");
    }
}
