// Autor: Athan Espinoza

//! Un campo de CSV listo para abrir en una planilla, en un solo lugar: lo
//! usan el export administrativo y el de auditoría (QA-40).
//!
//! Neutraliza la inyección de fórmulas (OWASP «CSV Injection»; PBL-13-002,
//! hallazgo real en Passbolt): un campo que empieza con `=`, `+`, `-`, `@`,
//! tab o CR lo interpreta Excel/Sheets/LibreOffice como fórmula, así que se
//! le antepone `'`. Después, el escapado RFC 4180: entre comillas si
//! contiene coma, comilla, CR o LF, duplicando las comillas internas.

pub fn campo(valor: &str) -> String {
    let neutralizado = if valor.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{valor}")
    } else {
        valor.to_string()
    };
    if neutralizado.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", neutralizado.replace('"', "\"\""))
    } else {
        neutralizado
    }
}

#[cfg(test)]
mod tests {
    use super::campo;

    #[test]
    fn neutraliza_formulas() {
        assert_eq!(campo("=HYPERLINK(\"http://x\")"), "\"'=HYPERLINK(\"\"http://x\"\")\"");
        assert_eq!(campo("+1"), "'+1");
        assert_eq!(campo("-2"), "'-2");
        assert_eq!(campo("@SUM(A1)"), "'@SUM(A1)");
        assert_eq!(campo("\tx"), "'\tx");
        assert_eq!(campo("\rx"), "\"'\rx\"");
    }

    #[test]
    fn escapa_rfc_4180_y_deja_lo_comun_igual() {
        assert_eq!(campo("hola"), "hola");
        assert_eq!(campo("a,b"), "\"a,b\"");
        assert_eq!(campo("dice \"hola\""), "\"dice \"\"hola\"\"\"");
        assert_eq!(campo("línea\nnueva"), "\"línea\nnueva\"");
        assert_eq!(campo("{\"a\":1}"), "\"{\"\"a\"\":1}\"");
    }
}
