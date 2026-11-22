// Autor: Athan Espinoza

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TextosLegales {
    pub privacy_url: Option<String>,
    pub terms_url: Option<String>,
}

/// Normaliza un link cargado por el admin: vacío es «sin link»; si no, tiene
/// que ser `http(s)://…`, sin espacios ni caracteres de control y de hasta
/// 512 caracteres (el frontend lo pone en un `href`: nada de `javascript:`).
pub fn normalizar_link(valor: Option<&str>) -> Result<Option<String>, &'static str> {
    let Some(v) = valor.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    let esquema_ok =
        v.get(..8).is_some_and(|p| p.eq_ignore_ascii_case("https://")) || v.get(..7).is_some_and(|p| p.eq_ignore_ascii_case("http://"));
    if !esquema_ok {
        return Err("el link tiene que empezar con https:// o http://");
    }
    if v.len() > 512 {
        return Err("el link no puede tener más de 512 caracteres");
    }
    if v.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("el link no puede tener espacios ni caracteres de control");
    }
    Ok(Some(v.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acepta_http_s_y_vacío() {
        assert_eq!(normalizar_link(None), Ok(None));
        assert_eq!(normalizar_link(Some("  ")), Ok(None));
        assert_eq!(
            normalizar_link(Some(" https://empresa.cl/privacidad ")),
            Ok(Some("https://empresa.cl/privacidad".into()))
        );
        assert_eq!(normalizar_link(Some("HTTP://intranet/legal")), Ok(Some("HTTP://intranet/legal".into())));
    }

    #[test]
    fn rechaza_otros_esquemas_y_basura() {
        for malo in [
            "javascript:alert(1)",
            "data:text/html,x",
            "empresa.cl/privacidad",
            "https://a b",
            "https://a\nb",
            "https://a\u{7}b",
        ] {
            assert!(normalizar_link(Some(malo)).is_err(), "{malo:?}");
        }
        assert!(normalizar_link(Some(&format!("https://{}", "a".repeat(510)))).is_err());
    }
}
