// Autor: Athan Espinoza

//! Comparación en tiempo constante — evita que el tiempo de respuesta filtre
//! información sobre en qué byte difiere un secreto comparado.

use subtle::ConstantTimeEq;

/// Compara dos hashes/tokens en tiempo constante — usar SIEMPRE en vez de `==`
/// para comparar cualquier valor derivado de un secreto (hash de token, session_hash,
/// fingerprint de clave pública para pinning).
pub fn secreto_coincide(esperado: &[u8], recibido: &[u8]) -> bool {
    esperado.ct_eq(recibido).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coincide_cuando_son_iguales() {
        assert!(secreto_coincide(b"mismo-valor", b"mismo-valor"));
    }

    #[test]
    fn no_coincide_cuando_difieren() {
        assert!(!secreto_coincide(b"valor-a", b"valor-b"));
    }

    #[test]
    fn no_coincide_con_longitudes_distintas() {
        assert!(!secreto_coincide(b"corto", b"mas-largo-que-corto"));
    }
}
