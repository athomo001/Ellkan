// Autor: Athan Espinoza

// Sin ventana de consola en Windows, también en debug: el `.exe` que se prueba
// a mano (windows\binarios) es un build de debug y mostraba una consola negra
// con el log al abrirlo. El log sigue yendo a `Ellkan.log` (LogDir de la app).
#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() {
  ellkan_desktop_lib::run();
}
