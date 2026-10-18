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

/// Modo lanzador de «Conectar»: `--lanzar <tubería> <modo> -- <programa> <args...>`.
///
/// Lo ejecuta la terminal (pestaña de Windows Terminal o consola de
/// PowerShell) en lugar del cliente. Lee el secreto de la tubería que publicó
/// la app (sólo este ejecutable puede leerla, una vez) y lanza el cliente con
/// el secreto en SU entorno: así funciona aunque la pestaña la cree un proceso
/// de Windows Terminal que no heredó nada de la app.
///
/// `modo`: `askpass` (ssh: este mismo ejecutable como `SSH_ASKPASS`) o
/// `env:<VARIABLE>` (psql/mysql). Si la tubería falla, el cliente arranca
/// igual sin secreto y lo pide en la terminal: degradación segura.
const ARG_LANZAR: &str = "--lanzar";

/// Variables que el lanzador acepta para entregar el secreto: no se deja
/// elegir una arbitraria (por ejemplo `PATH` o `COMSPEC`).
const VARIABLES_PERMITIDAS: &[&str] = &["PGPASSWORD", "MYSQL_PWD"];

/// Nombre corto válido de una tubería creada por la app.
fn nombre_de_tuberia_valido(nombre: &str) -> bool {
    nombre
        .strip_prefix("ellkan-conectar-")
        .is_some_and(|resto| resto.len() == 32 && resto.bytes().all(|b| b.is_ascii_hexdigit()))
}

#[derive(Debug, PartialEq, Eq)]
enum Entrega {
    Askpass,
    Variable(&'static str),
}

/// Valida `<tubería> <modo> -- <programa> <args...>`.
fn interpretar_lanzar(args: &[String]) -> Result<(&str, Entrega, &str, &[String]), String> {
    let [tuberia, modo, separador, programa, resto @ ..] = args else {
        return Err("uso: --lanzar <tubería> <modo> -- <programa> [args...]".into());
    };
    if separador != "--" {
        return Err("falta `--` antes del programa".into());
    }
    if !nombre_de_tuberia_valido(tuberia) {
        return Err("nombre de tubería inválido".into());
    }
    let entrega = match modo.as_str() {
        "askpass" => Entrega::Askpass,
        otro => {
            let variable = otro.strip_prefix("env:").unwrap_or_default();
            let permitida = VARIABLES_PERMITIDAS
                .iter()
                .find(|v| **v == variable)
                .ok_or_else(|| format!("modo de entrega no permitido: {otro}"))?;
            Entrega::Variable(permitida)
        }
    };
    Ok((tuberia.as_str(), entrega, programa.as_str(), resto))
}

fn leer_secreto(tuberia: &str) -> std::io::Result<zeroize::Zeroizing<String>> {
    use std::io::Read;
    let mut archivo = std::fs::File::open(format!(r"\\.\pipe\{tuberia}"))?;
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    let mut bloque = zeroize::Zeroizing::new([0u8; 512]);
    loop {
        match archivo.read(&mut bloque[..]) {
            Ok(0) => break,
            Ok(n) => bytes.extend_from_slice(&bloque[..n]),
            // 233 = ERROR_PIPE_NOT_CONNECTED: la app cerró su lado después de escribir.
            Err(e) if e.raw_os_error() == Some(233) || e.kind() == std::io::ErrorKind::BrokenPipe => break,
            Err(e) => return Err(e),
        }
    }
    if bytes.is_empty() {
        return Err(std::io::Error::other("la tubería no entregó nada"));
    }
    let texto = std::str::from_utf8(&bytes).map_err(|_| std::io::Error::other("secreto no es UTF-8"))?;
    Ok(zeroize::Zeroizing::new(texto.to_string()))
}

fn lanzar(args: &[String]) -> i32 {
    let (tuberia, entrega, programa, resto) = match interpretar_lanzar(args) {
        Ok(partes) => partes,
        Err(e) => {
            eprintln!("Ellkan: {e}");
            return 2;
        }
    };
    let mut comando = std::process::Command::new(programa);
    comando.args(resto);
    match leer_secreto(tuberia) {
        Ok(secreto) => match entrega {
            Entrega::Askpass => {
                if let Ok(yo) = std::env::current_exe() {
                    comando.env("SSH_ASKPASS_REQUIRE", "force");
                    comando.env("SSH_ASKPASS", yo);
                    comando.env("ELLKAN_ASKPASS_SECRET", secreto.as_str());
                }
            }
            Entrega::Variable(variable) => {
                comando.env(variable, secreto.as_str());
            }
        },
        Err(e) => eprintln!("Ellkan: no se pudo recibir la contraseña ({e}); escribila a mano cuando te la pidan."),
    }
    match comando.status() {
        Ok(estado) => estado.code().unwrap_or(1),
        Err(e) => {
            eprintln!("Ellkan: no se pudo ejecutar {programa}: {e}");
            1
        }
    }
}

fn main() {
    let argumentos: Vec<String> = std::env::args().skip(1).collect();
    if argumentos.first().map(String::as_str) == Some(ARG_LANZAR) {
        std::process::exit(lanzar(&argumentos[1..]));
    }
    let pregunta = argumentos.first().cloned().unwrap_or_default();
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

    fn v(partes: &[&str]) -> Vec<String> {
        partes.iter().map(|p| p.to_string()).collect()
    }

    const TUBERIA: &str = "ellkan-conectar-0123456789abcdef0123456789abcdef";

    #[test]
    fn lanzar_acepta_askpass_y_las_variables_permitidas() {
        let args = v(&[TUBERIA, "askpass", "--", "ssh.exe", "-p", "22", "u@h"]);
        let (t, e, p, r) = interpretar_lanzar(&args).unwrap();
        assert_eq!((t, e, p, r.len()), (TUBERIA, Entrega::Askpass, "ssh.exe", 3));
        let args = v(&[TUBERIA, "env:PGPASSWORD", "--", "psql.exe"]);
        assert_eq!(interpretar_lanzar(&args).unwrap().1, Entrega::Variable("PGPASSWORD"));
    }

    #[test]
    fn lanzar_rechaza_variables_y_tuberias_arbitrarias() {
        assert!(interpretar_lanzar(&v(&[TUBERIA, "env:PATH", "--", "x.exe"])).is_err());
        assert!(interpretar_lanzar(&v(&[TUBERIA, "env:", "--", "x.exe"])).is_err());
        assert!(interpretar_lanzar(&v(&["otra-tuberia", "askpass", "--", "x.exe"])).is_err());
        assert!(interpretar_lanzar(&v(&[r"..\pipe\x", "askpass", "--", "x.exe"])).is_err());
        assert!(interpretar_lanzar(&v(&[TUBERIA, "askpass", "x.exe"])).is_err());
        assert!(interpretar_lanzar(&v(&[TUBERIA, "askpass", "-x", "x.exe"])).is_err());
    }

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
