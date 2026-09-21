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
fn main() {
    if let Ok(secreto) = std::env::var("ELLKAN_ASKPASS_SECRET") {
        print!("{secreto}");
    }
}
