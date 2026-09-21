// Autor: Athan Espinoza

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

fn listar_archivos(raiz: &Path, actual: &Path, salida: &mut Vec<PathBuf>) {
  let Ok(entradas) = std::fs::read_dir(actual) else { return };
  for entrada in entradas.flatten() {
    let ruta = entrada.path();
    if ruta.is_dir() {
      listar_archivos(raiz, &ruta, salida);
    } else if let Ok(relativa) = ruta.strip_prefix(raiz) {
      salida.push(relativa.to_path_buf());
    }
  }
}

/// Punto 9: la extensión de navegador viaja DENTRO del ejecutable. Esto arma
/// `$OUT_DIR/extension_bundle.rs` con un `include_bytes!` por cada archivo de
/// `extension-bundle/<chromium|firefox>/` (lo deja ahí `app-escritorio/
/// scripts/preparar-extension.mjs` antes de compilar). Sin dependencias
/// nuevas y sin nada que leer en runtime. Si la carpeta no existe o está
/// vacía (un build de desarrollo que no preparó la extensión) el bundle queda
/// vacío y la app lo dice en vez de fallar la compilación.
fn generar_bundle_de_extension() {
  let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
  let bundle = manifest_dir.join("extension-bundle");
  // Si el directorio no existe Cargo recompila el script en cada build.
  let _ = std::fs::create_dir_all(&bundle);
  println!("cargo:rerun-if-changed=extension-bundle");

  let mut codigo = String::from("// Generado por build.rs — no editar.\npub static BUNDLE: &[(&str, &str, &[u8])] = &[\n");
  for objetivo in ["chromium", "firefox"] {
    let raiz = bundle.join(objetivo);
    let mut archivos = Vec::new();
    listar_archivos(&raiz, &raiz, &mut archivos);
    archivos.sort();
    for relativa in archivos {
      let ruta_relativa = relativa.to_string_lossy().replace('\\', "/");
      let ruta_absoluta = raiz.join(&relativa).to_string_lossy().replace('\\', "/");
      writeln!(codigo, "  ({objetivo:?}, {ruta_relativa:?}, include_bytes!({ruta_absoluta:?})),").unwrap();
    }
  }
  codigo.push_str("];\n");

  let salida = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR")).join("extension_bundle.rs");
  std::fs::write(salida, codigo).expect("no se pudo escribir extension_bundle.rs");
}

/// La versión de la app sale de `tauri.conf.json` (`build-windows.ps1 -Msi` la sube
/// sola), no del `Cargo.toml`, que comparten el servidor y la CLI. Se pasa al código
/// como `ELLKAN_VERSION` para que la pantalla de Ajustes muestre la misma que el MSI.
fn exportar_version_de_la_app() {
  let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
  let texto = std::fs::read_to_string(manifest_dir.join("tauri.conf.json")).expect("no se pudo leer tauri.conf.json");
  let json: serde_json::Value = serde_json::from_str(&texto).expect("tauri.conf.json no es un JSON válido");
  let version = json["version"].as_str().expect("tauri.conf.json no tiene `version`");
  println!("cargo:rustc-env=ELLKAN_VERSION={version}");
}

fn main() {
  // Asegura que Cargo recompile y vuelva a empaquetar los recursos web
  // cuando cambie el bundle estático del frontend o la configuración de Tauri,
  // evitando que se sirvan binarios desactualizados o cacheados sin interfaz.
  println!("cargo:rerun-if-changed=tauri.conf.json");
  println!("cargo:rerun-if-changed=../../frontend/build/index.html");

  exportar_version_de_la_app();
  generar_bundle_de_extension();

  tauri_build::build()
}
