// Autor: Athan Espinoza

//! Helper de `SSH_ASKPASS` (F-49, spec/13 §9) — un binario aparte y no un
//! script `.bat`/`.ps1` a propósito: imprimir un valor arbitrario con
//! `echo %VAR%` en un `.bat` reinterpreta caracteres como `&`/`|`/`^`/`%`
//! como metacaracteres de `cmd.exe` (probado en la sesión que motivó este
//! archivo — una contraseña generada con símbolos podría inyectar comandos
//! reales al conectar). Este binario no pasa por ningún parser de shell:
//! lee la variable de entorno y escribe los bytes tal cual a stdout, que es
//! exactamente el protocolo que espera `ssh` de su `SSH_ASKPASS`.
//!
//! `ELLKAN_ASKPASS_SECRET` la pone `conectar_recurso` (`lib.rs`) SÓLO en el
//! entorno del proceso `ssh` hijo (mismo patrón F-21 ya probado por la CLI:
//! env var sólo al hijo, nunca en `argv`/portapapeles/historial de shell).
//! Sin esa variable no imprime nada — `ssh` lo interpreta como "sin
//! contraseña" y vuelve a preguntar en la terminal, degradación segura en
//! vez de un fallo silencioso.
//!
//! Con `SSH_ASKPASS_REQUIRE=force`, `ssh` manda por acá TODAS sus preguntas,
//! no sólo la contraseña. En particular la de confianza en el servidor la
//! primera vez que te conectás («Are you sure you want to continue connecting
//! (yes/no/[fingerprint])?»): contestarle la contraseña hacía que `ssh` la
//! repitiera sin fin y la terminal quedara colgada. Esa pregunta se le hace a
//! la persona en un cuadro de Windows con la huella a la vista, y nunca se
//! acepta sola.

/// Qué espera `ssh` que se le conteste.
#[derive(Debug, PartialEq, Eq)]
enum Pregunta {
    /// Pedir confianza en el servidor (yes/no).
    Confirmar,
    /// Sólo mostrar un mensaje; no hay nada que contestar.
    Informar,
    /// Contraseña (o cualquier otro dato secreto).
    Secreto,
}

/// `modo` es `SSH_ASKPASS_PROMPT` (OpenSSH 8.9+); en versiones anteriores no
/// existe y sólo queda el texto de la pregunta.
fn clasificar(pregunta: &str, modo: Option<&str>) -> Pregunta {
    match modo {
        Some("confirm") => return Pregunta::Confirmar,
        Some("none") => return Pregunta::Informar,
        _ => {}
    }
    let p = pregunta.to_ascii_lowercase();
    if p.contains("yes/no") || p.contains("'yes', 'no'") {
        Pregunta::Confirmar
    } else {
        Pregunta::Secreto
    }
}

/// Texto del cuadro: la huella y el nombre del servidor (lo que `ssh` mostró)
/// sin su última línea en inglés, que se reemplaza por la pregunta en español.
fn texto_confirmacion(pregunta: &str) -> String {
    let detalle: Vec<&str> = pregunta
        .lines()
        .map(str::trim_end)
        .filter(|l| !l.trim().is_empty() && !l.contains("Are you sure") && !l.contains("yes/no") && !l.contains("'yes', 'no'"))
        .collect();
    let detalle = if detalle.is_empty() { pregunta.trim().to_string() } else { detalle.join("\n") };
    format!(
        "Es la primera vez que este equipo se conecta a este servidor. Comprueba que la huella sea la de tu servidor antes de continuar.\n\n{detalle}\n\n\u{BF}Confiar en este servidor y continuar?"
    )
}

#[cfg(windows)]
fn confirmar(texto: &str) -> bool {
    use windows::core::PCWSTR;
    use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, IDYES, MB_DEFBUTTON2, MB_ICONQUESTION, MB_SETFOREGROUND, MB_TOPMOST, MB_YESNO};

    let a_utf16 = |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };
    let texto = a_utf16(texto);
    let titulo = a_utf16("Ellkan \u{2014} servidor SSH nuevo");
    // SAFETY: los dos buffers terminan en nulo y viven durante la llamada.
    unsafe { MessageBoxW(None, PCWSTR(texto.as_ptr()), PCWSTR(titulo.as_ptr()), MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2 | MB_SETFOREGROUND | MB_TOPMOST) == IDYES }
}

#[cfg(not(windows))]
fn confirmar(_texto: &str) -> bool {
    false
}

fn main() {
    let pregunta = std::env::args().nth(1).unwrap_or_default();
    let modo = std::env::var("SSH_ASKPASS_PROMPT").ok();

    match clasificar(&pregunta, modo.as_deref()) {
        Pregunta::Informar => {}
        Pregunta::Confirmar => {
            // En modo `confirm` `ssh` mira el código de salida; en las versiones
            // anteriores lee la respuesta de stdout. Se cubren las dos.
            if confirmar(&texto_confirmacion(&pregunta)) {
                print!("yes");
            } else {
                print!("no");
                std::process::exit(1);
            }
        }
        Pregunta::Secreto => {
            if let Ok(secreto) = std::env::var("ELLKAN_ASKPASS_SECRET") {
                print!("{secreto}");
            }
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    const HUELLA: &str = "The authenticity of host 'srv (10.0.0.5)' can't be established.\nED25519 key fingerprint is SHA256:abc123.\nThis key is not known by any other names.\nAre you sure you want to continue connecting (yes/no/[fingerprint])? ";

    #[test]
    fn la_pregunta_de_confianza_no_se_contesta_con_la_contrasena() {
        assert_eq!(clasificar(HUELLA, None), Pregunta::Confirmar);
        assert_eq!(clasificar("Are you sure you want to continue connecting (yes/no)? ", None), Pregunta::Confirmar);
        assert_eq!(clasificar("Please type 'yes', 'no' or the fingerprint: ", None), Pregunta::Confirmar);
    }

    #[test]
    fn el_modo_de_openssh_manda_sobre_el_texto() {
        assert_eq!(clasificar("cualquier cosa", Some("confirm")), Pregunta::Confirmar);
        assert_eq!(clasificar("cualquier cosa", Some("none")), Pregunta::Informar);
    }

    #[test]
    fn la_contrasena_y_lo_demas_siguen_recibiendo_el_secreto() {
        assert_eq!(clasificar("z@localhost's password: ", None), Pregunta::Secreto);
        assert_eq!(clasificar("Enter passphrase for key 'id_ed25519': ", None), Pregunta::Secreto);
        assert_eq!(clasificar("", None), Pregunta::Secreto);
        assert_eq!(clasificar("z@srv's password: ", Some("")), Pregunta::Secreto);
    }

    #[test]
    fn el_cuadro_muestra_la_huella_y_no_la_pregunta_en_ingles() {
        let t = texto_confirmacion(HUELLA);
        assert!(t.contains("SHA256:abc123"));
        assert!(t.contains("srv (10.0.0.5)"));
        assert!(!t.contains("Are you sure"));
        assert!(t.ends_with("\u{BF}Confiar en este servidor y continuar?"));
    }

    #[test]
    fn si_no_hay_detalle_se_muestra_el_texto_completo() {
        let t = texto_confirmacion("Continue (yes/no)?");
        assert!(t.contains("Continue (yes/no)?"));
    }
}
