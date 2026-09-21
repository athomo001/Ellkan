// Autor: Athan Espinoza

//! Punto 9 de la lista de pendientes de escritorio: instalar la extensión de
//! navegador DESDE la app de escritorio. La extensión viaja embebida en el
//! ejecutable (la arma `src-tauri/build.rs` a partir de la carpeta
//! `extension-bundle/`), así que cada build de la app trae la última versión
//! de la extensión que se haya preparado.
//!
//! Este módulo es la parte sin Tauri: extraer el bundle a una carpeta estable,
//! leer la versión instalada y decidir si hay que actualizar. Recibe los
//! archivos como parámetro (no sabe de dónde salen), por eso se puede probar
//! sin compilar el shell gráfico.
//!
//! **Por qué una carpeta fija y no un archivo suelto**: los navegadores de
//! base Chromium instalan una extensión sin empaquetar apuntando a una carpeta
//! ("Cargar descomprimida") y la releen desde ahí en cada arranque. Si esa
//! carpeta se refresca cuando la app se actualiza, la extensión se actualiza
//! sola sin que el usuario vuelva a instalar nada.

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

use anyhow::{bail, Context};

/// Un archivo del bundle: ruta relativa con `/` (ej. `popup/index.html`).
pub struct ArchivoExtension<'a> {
    pub ruta: &'a str,
    pub contenido: &'a [u8],
}

/// Navegadores soportados y el build de la extensión que usa cada uno.
/// Chrome, Edge, Brave y Opera (base Chromium) comparten un único build y una
/// única carpeta — cada uno la carga por su cuenta. Firefox usa su propio
/// manifest.
pub const NAVEGADORES: &[(&str, &str)] =
    &[("chrome", "chromium"), ("edge", "chromium"), ("brave", "chromium"), ("opera", "chromium"), ("firefox", "firefox")];

/// Build de la extensión que corresponde a `navegador`, `None` si no es uno
/// de los soportados — nunca se arma una ruta a partir de un id sin validar.
pub fn objetivo_de(navegador: &str) -> Option<&'static str> {
    NAVEGADORES.iter().find(|(id, _)| *id == navegador).map(|(_, objetivo)| *objetivo)
}

/// Nombre de la carpeta donde queda la extensión. Se ve: el usuario la elige
/// a mano en el diálogo "Cargar descomprimida" del navegador, así que el
/// nombre tiene que decirle qué es (y qué navegador la usa).
pub fn nombre_de_carpeta(objetivo: &str) -> &'static str {
    match objetivo {
        "firefox" => "Ellkan extensión Firefox",
        _ => "Ellkan extensión",
    }
}

/// Carpeta dentro de `base` donde se extrae la extensión de `objetivo`.
pub fn carpeta_en(base: &Path, objetivo: &str) -> PathBuf {
    base.join(nombre_de_carpeta(objetivo))
}

/// Dónde se extrae la extensión: en **Documentos** del usuario, porque es
/// donde el diálogo de carpeta del navegador abre por defecto — así el usuario
/// ve la carpeta "Ellkan extensión" al abrirlo, sin tener que pegar ni tipear
/// ninguna ruta (la primera versión la dejaba en una carpeta oculta y en las
/// pruebas reales el usuario terminó eligiendo "Documentos" en vez de la
/// carpeta de la extensión). `ELLKAN_EXTENSION_DIR` la redirige (pruebas y
/// varias identidades en la misma máquina, mismo criterio que
/// `ELLKAN_CONFIG_DIR`). Si Documentos no se puede resolver, cae a
/// `~/.ellkan/extension`.
pub fn carpeta_de_instalacion(objetivo: &str) -> PathBuf {
    let base = std::env::var_os("ELLKAN_EXTENSION_DIR")
        .map(PathBuf::from)
        .or_else(dirs::document_dir)
        .or_else(|| super::dir_home_ellkan().ok().map(|d| d.join("extension")))
        .unwrap_or_else(|| PathBuf::from("."));
    carpeta_en(&base, objetivo)
}

/// Página donde cada navegador administra sus extensiones — donde el usuario
/// tiene que hacer el paso que el navegador no deja hacer desde afuera.
pub fn pagina_extensiones(navegador: &str) -> Option<&'static str> {
    match navegador {
        "chrome" => Some("chrome://extensions"),
        "edge" => Some("edge://extensions"),
        "brave" => Some("brave://extensions"),
        "opera" => Some("opera://extensions"),
        "firefox" => Some("about:debugging#/runtime/this-firefox"),
        _ => None,
    }
}

/// Rutas donde Windows instala cada navegador. `entorno` resuelve las
/// variables (`ProgramFiles`, `LOCALAPPDATA`…) y se inyecta para poder
/// probarlo sin depender de la máquina. Devuelve candidatos, no confirma que
/// existan.
pub fn candidatos_ejecutable(navegador: &str, entorno: &dyn Fn(&str) -> Option<String>) -> Vec<PathBuf> {
    let mut rutas = Vec::new();
    let mut agregar = |variable: &str, partes: &[&str]| {
        if let Some(base) = entorno(variable) {
            let mut ruta = PathBuf::from(base);
            ruta.extend(partes);
            rutas.push(ruta);
        }
    };
    match navegador {
        "chrome" => {
            for base in ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"] {
                agregar(base, &["Google", "Chrome", "Application", "chrome.exe"]);
            }
        }
        "edge" => {
            for base in ["ProgramFiles(x86)", "ProgramFiles"] {
                agregar(base, &["Microsoft", "Edge", "Application", "msedge.exe"]);
            }
        }
        "brave" => {
            for base in ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"] {
                agregar(base, &["BraveSoftware", "Brave-Browser", "Application", "brave.exe"]);
            }
        }
        "opera" => {
            agregar("LOCALAPPDATA", &["Programs", "Opera", "opera.exe"]);
            agregar("ProgramFiles", &["Opera", "opera.exe"]);
            agregar("ProgramFiles(x86)", &["Opera", "opera.exe"]);
        }
        "firefox" => {
            for base in ["ProgramFiles", "ProgramFiles(x86)"] {
                agregar(base, &["Mozilla Firefox", "firefox.exe"]);
            }
        }
        _ => {}
    }
    rutas
}

#[cfg(not(windows))]
fn nombres_en_path(navegador: &str) -> &'static [&'static str] {
    match navegador {
        "chrome" => &["google-chrome", "google-chrome-stable"],
        "edge" => &["microsoft-edge", "microsoft-edge-stable"],
        "brave" => &["brave-browser", "brave"],
        "opera" => &["opera"],
        "firefox" => &["firefox"],
        _ => &[],
    }
}

/// Ejecutable del navegador si está instalado en esta máquina. Es lo que
/// decide qué navegadores se ofrecen: no tiene sentido listar Opera a quien
/// no lo tiene.
pub fn buscar_ejecutable(navegador: &str) -> Option<PathBuf> {
    buscar_ejecutable_en(navegador, std::env::var_os("ELLKAN_NAVEGADORES_DIR").map(PathBuf::from).as_deref())
}

/// Igual que `buscar_ejecutable`, pero con `carpeta_de_pruebas` (variable
/// `ELLKAN_NAVEGADORES_DIR`) sólo se mira ahí: `<carpeta>/<navegador>[.exe]`.
/// Existe para probar la app real sin abrir el navegador de verdad de quien
/// corre la prueba — en Windows ni siquiera se puede redirigir `ProgramFiles`
/// por entorno, así que las rutas de instalación no se pueden simular.
pub fn buscar_ejecutable_en(navegador: &str, carpeta_de_pruebas: Option<&Path>) -> Option<PathBuf> {
    if let Some(carpeta) = carpeta_de_pruebas {
        // Sólo ids soportados: nunca se arma una ruta con lo que llegue de afuera.
        objetivo_de(navegador)?;
        let nombre = if cfg!(windows) { format!("{navegador}.exe") } else { navegador.to_string() };
        return Some(carpeta.join(nombre)).filter(|ruta| ruta.is_file());
    }

    #[cfg(windows)]
    {
        candidatos_ejecutable(navegador, &|variable| std::env::var(variable).ok()).into_iter().find(|ruta| ruta.is_file())
    }
    #[cfg(not(windows))]
    {
        let path = std::env::var_os("PATH")?;
        nombres_en_path(navegador)
            .iter()
            .find_map(|nombre| std::env::split_paths(&path).map(|dir| dir.join(nombre)).find(|candidato| candidato.is_file()))
    }
}

/// Abre el navegador directamente en su página de extensiones. Ni el
/// ejecutable ni la URL salen de nada que escriba el usuario: los dos se
/// resuelven desde `navegador` contra tablas fijas.
pub fn abrir_pagina_de_extensiones(navegador: &str) -> anyhow::Result<()> {
    let url = pagina_extensiones(navegador).with_context(|| format!("navegador no soportado: {navegador}"))?;
    let ejecutable = buscar_ejecutable(navegador).with_context(|| format!("no se encontró {navegador} instalado en este equipo"))?;
    std::process::Command::new(&ejecutable)
        .arg(url)
        .spawn()
        .with_context(|| format!("no se pudo abrir {}", ejecutable.display()))?;
    Ok(())
}

/// Ruta relativa segura dentro de la carpeta de destino: sin absolutas, sin
/// `..`, sin `.`, sin prefijos de unidad. Los archivos salen de nuestro propio
/// build, pero un bundle mal armado nunca debería poder escribir afuera de la
/// carpeta de la extensión.
fn ruta_segura(ruta: &str) -> anyhow::Result<PathBuf> {
    if ruta.is_empty() {
        bail!("ruta vacía en el bundle de la extensión");
    }
    let mut limpia = PathBuf::new();
    for componente in Path::new(ruta).components() {
        match componente {
            Component::Normal(parte) => limpia.push(parte),
            _ => bail!("ruta insegura en el bundle de la extensión: {ruta:?}"),
        }
    }
    Ok(limpia)
}

/// Campo `version` de un `manifest.json`, `None` si no parsea o no lo trae.
pub fn version_de_manifest(bytes: &[u8]) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(bytes).ok()?.get("version")?.as_str().map(str::to_string)
}

/// Versión de la extensión que trae ESTA build de la app.
pub fn version_incluida(archivos: &[ArchivoExtension<'_>]) -> Option<String> {
    archivos.iter().find(|a| a.ruta == "manifest.json").and_then(|a| version_de_manifest(a.contenido))
}

/// Versión de la extensión que ya está extraída en `destino`, si hay una.
pub fn version_instalada(destino: &Path) -> Option<String> {
    std::fs::read(destino.join("manifest.json")).ok().and_then(|bytes| version_de_manifest(&bytes))
}

/// `true` si `destino` ya tiene exactamente la versión que trae el bundle.
pub fn esta_al_dia(destino: &Path, archivos: &[ArchivoExtension<'_>]) -> bool {
    match (version_instalada(destino), version_incluida(archivos)) {
        (Some(instalada), Some(incluida)) => instalada == incluida,
        _ => false,
    }
}

fn listar_archivos(raiz: &Path, actual: &Path, salida: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entrada in std::fs::read_dir(actual)? {
        let entrada = entrada?;
        let ruta = entrada.path();
        if entrada.file_type()?.is_dir() {
            listar_archivos(raiz, &ruta, salida)?;
        } else if let Ok(relativa) = ruta.strip_prefix(raiz) {
            salida.push(relativa.to_path_buf());
        }
    }
    Ok(())
}

/// Archivo que la app deja DENTRO de la carpeta de la extensión con la
/// dirección de su backend local. El puerto lo elige la app (rango dinámico,
/// persistido) y el usuario no tiene cómo saberlo: la extensión lo lee de acá
/// para traer el servidor ya puesto en su pantalla de login. No forma parte
/// del bundle, así que `instalar` lo respeta al limpiar obsoletos.
pub const ARCHIVO_CONEXION: &str = "ellkan-escritorio.json";

/// Dirección del backend local de la app en `puerto`.
pub fn url_backend(puerto: u16) -> String {
    format!("http://127.0.0.1:{puerto}")
}

/// Deja en `destino` el archivo con la dirección del backend local. No lo
/// reescribe si ya está igual (se llama en cada arranque).
pub fn escribir_conexion(destino: &Path, puerto: u16) -> anyhow::Result<()> {
    let contenido = serde_json::to_vec_pretty(&serde_json::json!({ "server_url": url_backend(puerto) }))?;
    let ruta = destino.join(ARCHIVO_CONEXION);
    if std::fs::read(&ruta).is_ok_and(|actual| actual == contenido) {
        return Ok(());
    }
    std::fs::create_dir_all(destino).with_context(|| format!("no se pudo crear {}", destino.display()))?;
    std::fs::write(&ruta, contenido).with_context(|| format!("no se pudo escribir {}", ruta.display()))
}

/// Elimina de `destino` lo que ya no está en el bundle (por ejemplo los
/// `popup/assets/index-<hash>.js` de una versión anterior) y las carpetas que
/// quedan vacías.
fn limpiar_obsoletos(destino: &Path, vigentes: &HashSet<PathBuf>) -> std::io::Result<()> {
    let mut existentes = Vec::new();
    listar_archivos(destino, destino, &mut existentes)?;
    for relativa in existentes {
        if relativa != Path::new(ARCHIVO_CONEXION) && !vigentes.contains(&relativa) {
            std::fs::remove_file(destino.join(&relativa))?;
        }
    }
    quitar_carpetas_vacias(destino, destino)
}

fn quitar_carpetas_vacias(raiz: &Path, actual: &Path) -> std::io::Result<()> {
    for entrada in std::fs::read_dir(actual)? {
        let ruta = entrada?.path();
        if ruta.is_dir() {
            quitar_carpetas_vacias(raiz, &ruta)?;
            if ruta != raiz && std::fs::read_dir(&ruta)?.next().is_none() {
                std::fs::remove_dir(&ruta)?;
            }
        }
    }
    Ok(())
}

/// Extrae el bundle en `destino`, pisando lo que haya y sacando lo obsoleto.
///
/// Escribe en el lugar (no borra y recrea la carpeta) para que la ruta que el
/// navegador ya tiene registrada siga siendo válida durante la actualización,
/// y deja `manifest.json` para lo ÚLTIMO: si algo falla a la mitad, la versión
/// instalada sigue siendo la vieja y el próximo arranque reintenta, en vez de
/// declarar "al día" una carpeta a medio escribir.
pub fn instalar(destino: &Path, archivos: &[ArchivoExtension<'_>]) -> anyhow::Result<()> {
    if archivos.is_empty() {
        bail!("esta build de Ellkan no incluye la extensión de navegador");
    }

    // Se validan TODAS las rutas antes de escribir nada.
    let mut a_escribir: Vec<(PathBuf, &ArchivoExtension<'_>)> =
        archivos.iter().map(|a| ruta_segura(a.ruta).map(|r| (r, a))).collect::<anyhow::Result<_>>()?;
    a_escribir.sort_by_key(|(ruta, _)| ruta.as_path() == Path::new("manifest.json"));

    std::fs::create_dir_all(destino).with_context(|| format!("no se pudo crear {}", destino.display()))?;
    for (relativa, archivo) in &a_escribir {
        let ruta = destino.join(relativa);
        if let Some(padre) = ruta.parent() {
            std::fs::create_dir_all(padre).with_context(|| format!("no se pudo crear {}", padre.display()))?;
        }
        std::fs::write(&ruta, archivo.contenido).with_context(|| format!("no se pudo escribir {}", ruta.display()))?;
    }

    let vigentes: HashSet<PathBuf> = a_escribir.into_iter().map(|(relativa, _)| relativa).collect();
    limpiar_obsoletos(destino, &vigentes).with_context(|| format!("no se pudo limpiar {}", destino.display()))?;
    Ok(())
}
