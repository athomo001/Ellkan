// Autor: Athan Espinoza

//! «Conectar» en terminal: la app publica el secreto en una tubería de un solo
//! uso y `ellkan_askpass.exe --lanzar` lo recibe y se lo pasa al cliente por
//! su entorno. Se prueba con procesos reales (el lanzador compilado y `cmd`
//! como cliente que imprime la variable).
#![cfg(windows)]

use std::path::Path;
use std::process::Command;

use ellkan_desktop_lib::tuberia::{ruta_de, servir_secreto_una_vez};
use zeroize::Zeroizing;

const LANZADOR: &str = env!("CARGO_BIN_EXE_ellkan_askpass");

/// Lanza `cmd /c set PGPASSWORD` a través del lanzador y devuelve lo que imprimió.
fn lanzar_set(tuberia: &str) -> String {
  let salida = Command::new(LANZADOR)
    .args(["--lanzar", tuberia, "env:PGPASSWORD", "--", "cmd.exe", "/d", "/c", "set", "PGPASSWORD"])
    .env_remove("PGPASSWORD")
    .output()
    .unwrap();
  String::from_utf8_lossy(&salida.stdout).into_owned()
}

#[test]
fn el_lanzador_recibe_el_secreto_una_sola_vez() {
  // Con metacaracteres de shell: viaja como bytes, no pasa por ningún intérprete.
  let secreto = "s3cr3to;&|^%x";
  let tuberia = servir_secreto_una_vez(Zeroizing::new(secreto.to_string()), Path::new(LANZADOR)).unwrap();

  let primera = lanzar_set(&tuberia);
  assert!(primera.contains(&format!("PGPASSWORD={secreto}")), "el cliente no recibió el secreto: {primera:?}");

  let segunda = lanzar_set(&tuberia);
  assert!(!segunda.contains(secreto), "la tubería entregó el secreto dos veces");
}

#[test]
fn otro_proceso_no_recibe_el_secreto() {
  use std::io::Read;

  let secreto = "solo-para-el-lanzador";
  let tuberia = servir_secreto_una_vez(Zeroizing::new(secreto.to_string()), Path::new(LANZADOR)).unwrap();

  // Este proceso de prueba no es el lanzador: se lo desconecta sin escribirle nada.
  let mut leido = Vec::new();
  if let Ok(mut f) = std::fs::File::open(ruta_de(&tuberia)) {
    let _ = f.read_to_end(&mut leido);
  }
  assert!(leido.is_empty(), "un proceso ajeno leyó {} bytes de la tubería", leido.len());

  // Y el lanzador legítimo lo sigue recibiendo después.
  let salida = lanzar_set(&tuberia);
  assert!(salida.contains(&format!("PGPASSWORD={secreto}")), "el lanzador no lo recibió tras el intento ajeno: {salida:?}");
}

#[test]
fn sin_tuberia_el_cliente_arranca_igual_sin_secreto() {
  let salida = lanzar_set("ellkan-conectar-00000000000000000000000000000000");
  assert!(!salida.contains("PGPASSWORD="), "no debería haber variable: {salida:?}");
}
