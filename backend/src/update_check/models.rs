// Autor: Athan Espinoza

use time::OffsetDateTime;

/// Lo guardado en `update_check` (una sola fila).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EstadoAviso {
    pub enabled: bool,
    pub latest_version: Option<String>,
    pub release_url: Option<String>,
    pub checked_at: Option<OffsetDateTime>,
}

/// La última Release, ya validada: versión `X.Y.Z` y link de GitHub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UltimaVersion {
    pub version: String,
    pub url: String,
}

/// `X.Y.Z` → `(X, Y, Z)`. Acepta una `v` adelante (los tags son `vX.Y.Z`);
/// cualquier otra cosa (sufijos `-dev.N`, texto) es `None`.
pub fn parsear_version(v: &str) -> Option<(u64, u64, u64)> {
    let v = v.strip_prefix('v').unwrap_or(v);
    let mut partes = v.split('.');
    let (a, b, c) = (partes.next()?, partes.next()?, partes.next()?);
    if partes.next().is_some() {
        return None;
    }
    let num = |s: &str| (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())).then(|| s.parse::<u64>().ok()).flatten();
    Some((num(a)?, num(b)?, num(c)?))
}

/// Versión de este servidor: la que el build de la imagen fija en
/// `ELLKAN_BUILD_VERSION` (la de la Release). Un build sin ella (desarrollo) no
/// tiene número y no se compara.
pub fn version_actual() -> Option<&'static str> {
    option_env!("ELLKAN_BUILD_VERSION").filter(|v| parsear_version(v).is_some())
}

/// ¿`ultima` es más nueva que `actual`?
pub fn hay_version_nueva(actual: Option<&str>, ultima: Option<&str>) -> bool {
    match (actual.and_then(parsear_version), ultima.and_then(parsear_version)) {
        (Some(a), Some(u)) => u > a,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parsea_sólo_x_y_z() {
        assert_eq!(parsear_version("0.1.70"), Some((0, 1, 70)));
        assert_eq!(parsear_version("v1.2.3"), Some((1, 2, 3)));
        for malo in ["", "1.2", "1.2.3.4", "v1.2.3-dev.5", "1.x.3", "1..3", "+1.2.3"] {
            assert_eq!(parsear_version(malo), None, "{malo:?}");
        }
    }

    #[test]
    fn compara_numéricamente() {
        assert!(hay_version_nueva(Some("0.1.9"), Some("v0.1.10")));
        assert!(!hay_version_nueva(Some("0.1.10"), Some("v0.1.10")));
        assert!(!hay_version_nueva(Some("0.2.0"), Some("v0.1.99")));
        // Sin número propio (build de desarrollo) nunca avisa.
        assert!(!hay_version_nueva(None, Some("v9.9.9")));
        assert!(!hay_version_nueva(Some("0.1.0"), None));
    }
}
