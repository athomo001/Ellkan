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

/// Código de un solo uso de `digitos` cifras (1 a 9), uniforme. QA-41:
/// `u32 % 10^n` favorece los valores bajos (2^32 no es múltiplo de 10^n);
/// con muestreo por rechazo se descarta la franja final incompleta y cada
/// código tiene exactamente la misma probabilidad.
pub fn codigo_numerico(digitos: u32) -> String {
    assert!((1..=9).contains(&digitos), "un código numérico va de 1 a 9 dígitos");
    let modulo = 10u64.pow(digitos);
    // Mayor múltiplo de `modulo` que cabe en el rango de un u32.
    let zona_uniforme = ((1u64 << 32) / modulo) * modulo;
    loop {
        let n = u64::from(u32::from_be_bytes(bytes_aleatorios::<4>()));
        if n < zona_uniforme {
            return format!("{:0ancho$}", n % modulo, ancho = digitos as usize);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codigo_numerico_tiene_el_largo_pedido_y_solo_digitos() {
        for digitos in [1, 6, 8, 9] {
            for _ in 0..200 {
                let c = codigo_numerico(digitos);
                assert_eq!(c.len(), digitos as usize, "{c}");
                assert!(c.bytes().all(|b| b.is_ascii_digit()), "{c}");
            }
        }
    }

    #[test]
    fn codigo_numerico_de_un_digito_cubre_todos_los_valores() {
        let vistos: std::collections::HashSet<String> = (0..1000).map(|_| codigo_numerico(1)).collect();
        assert_eq!(vistos.len(), 10);
    }

    #[test]
    fn bytes_aleatorios_no_son_todos_cero() {
        let a: [u8; 32] = bytes_aleatorios();
        let b: [u8; 32] = bytes_aleatorios();
        assert_ne!(a, [0u8; 32]);
        assert_ne!(a, b, "dos llamadas no deberían coincidir");
    }
}
