// Autor: Athan Espinoza

use std::path::{Path, PathBuf};

use tauri::Manager;
use zeroize::Zeroizing;

mod portable;
mod sistema;

/// Resuelve el directorio de datos según el sistema operativo:
/// - Windows: `%APPDATA%\Ellkan`
/// - Linux: `$XDG_DATA_HOME/ellkan` o fallback a `$HOME/.local/share/ellkan`
fn datadir() -> PathBuf {
  // Modo portable (F-54): los datos van junto al `.exe`.
  if let Some(datos) = portable::carpeta_de_datos() {
    return datos;
  }

  #[cfg(target_os = "windows")]
  {
    let appdata = std::env::var("APPDATA").expect("Variable de entorno APPDATA debe existir en Windows");
    PathBuf::from(appdata).join("Ellkan")
  }

  #[cfg(target_os = "linux")]
  {
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
      PathBuf::from(xdg).join("ellkan")
    } else {
      let home = std::env::var("HOME").expect("Variable de entorno HOME debe existir en Linux");
      PathBuf::from(home).join(".local").join("share").join("ellkan")
    }
  }

  #[cfg(not(any(target_os = "windows", target_os = "linux")))]
  {
    PathBuf::from("ellkan-data")
  }
}

/// Borra todo lo que la app guardó del usuario: la carpeta de datos (bóveda,
/// ajustes, copias), los datos de la ventana (idioma, tema, sesión), el
/// `desktop.json` y las claves del llavero. Lo llama el desinstalador SÓLO si el
/// usuario lo pidió. No toca lo demás de `~/.ellkan` (lo comparte la CLI).
fn borrar_datos_del_usuario() {
  let mut carpetas = vec![datadir()];
  if let Some(local) = std::env::var_os("LOCALAPPDATA") {
    carpetas.push(PathBuf::from(local).join("com.ellkan.desktop"));
  }
  for carpeta in &carpetas {
    if let Err(e) = sistema::borrar_carpeta_de_datos(carpeta) {
      eprintln!("{e}");
    }
  }
  let config = std::env::var_os("ELLKAN_CONFIG_DIR")
    .map(PathBuf::from)
    .or_else(|| std::env::var_os("USERPROFILE").map(|u| PathBuf::from(u).join(".ellkan")));
  if let Some(config) = config {
    let _ = std::fs::remove_file(config.join("desktop.json"));
  }
  sistema::borrar_credenciales_llavero();
}

/// Puerto real ya bindeado (spec/13 §3) — el SPA lo lee vía el comando
/// `puerto_backend` en vez de un valor hardcodeado, porque desde
/// 2026-09-16 el puerto es dinámico (`ellkan_backend::desktop::
/// bindear_puerto`: reusa el fijo persistido, o autoelige uno libre del
/// rango IANA privado en el primer arranque).
struct PuertoBackend(u16);

#[tauri::command]
fn puerto_backend(estado: tauri::State<PuertoBackend>) -> u16 {
  estado.0
}

/// Puerto fijo persistido en `<datadir>/config.json` (spec/13 §3) — `None`
/// si todavía nadie lo confirmó (hoy: siempre el autoelegido en el primer
/// arranque, ver `bindear_puerto`). Se usa en Ajustes para mostrar qué hay
/// guardado, junto al puerto REAL de esta sesión (`puerto_backend`, que
/// puede diferir si el fijo dejó de estar disponible — `bindear_puerto` cae
/// a uno libre sin romper el arranque).
#[tauri::command]
fn puerto_configurado() -> Result<Option<u16>, String> {
  let config = ellkan_backend::desktop::cargar_config(&datadir()).map_err(|e| format!("no se pudo leer la configuración: {e:#}"))?;
  Ok(config.puerto_fijo)
}

#[derive(serde::Serialize)]
struct ResultadoConfigurarPuerto {
  advertencia: Option<String>,
}

/// Paso de wizard/Ajustes (spec/13 §3) que hasta ahora no existía: dejar
/// que el usuario ELIJA o confirme el puerto fijo, en vez de heredar
/// siempre el que `bindear_puerto` autoeligió en el primer arranque.
/// Validación en dos capas tal como pide la spec: rechazo duro de
/// `0-1023` (reservados por el SO, nunca bindeables sin privilegios) +
/// advertencia no bloqueante sobre puertos de uso común. El bind de
/// prueba (bindea y suelta enseguida) confirma disponibilidad REAL antes
/// de guardar — nunca persiste un puerto que ni siquiera pudo abrirse.
///
/// **Efecto diferido, no inmediato**: el backend de esta sesión ya está
/// escuchando en el puerto que `bindear_puerto` resolvió al arrancar — acá
/// sólo se persiste la elección para el PRÓXIMO arranque (rebindear en
/// caliente movería el `TcpListener` que `axum::serve` ya está sirviendo,
/// bastante más riesgoso que pedirle al usuario que reinicie una vez). El
/// frontend es responsable de comunicar ese delay.
#[tauri::command]
async fn configurar_puerto_fijo(puerto: u16) -> Result<ResultadoConfigurarPuerto, String> {
  if puerto < 1024 {
    return Err(format!(
      "El puerto {puerto} está reservado por el sistema operativo — elegí uno de 1024 en adelante (se sugiere el rango 49152-65535)."
    ));
  }

  // Bind de prueba real: confirma disponibilidad ahora mismo. El listener
  // se suelta al salir de scope (nunca se guarda ni se sirve nada en él) —
  // no elimina la posibilidad de una carrera con otro proceso entre este
  // chequeo y el próximo arranque real, pero es la misma garantía (ni más
  // ni menos) que ya acepta `bindear_puerto` para el puerto autoelegido.
  tokio::net::TcpListener::bind(("127.0.0.1", puerto))
    .await
    .map_err(|e| format!("el puerto {puerto} no está disponible ahora mismo: {e}"))?;

  const PUERTOS_COMUNES: &[u16] = &[80, 443, 1433, 3000, 3306, 5000, 5432, 6379, 8000, 8080, 8443, 27017];
  let advertencia = PUERTOS_COMUNES.contains(&puerto).then(|| {
    format!("El puerto {puerto} lo usa habitualmente otro servicio (bases de datos, otros servidores locales) — puede chocar más adelante si esa otra app corre en esta misma máquina. Podés confirmarlo igual.")
  });

  let dir = datadir();
  let mut config = ellkan_backend::desktop::cargar_config(&dir).map_err(|e| format!("no se pudo leer la configuración: {e:#}"))?;
  config.puerto_fijo = Some(puerto);
  ellkan_backend::desktop::guardar_config(&dir, &config).map_err(|e| format!("no se pudo guardar la configuración: {e:#}"))?;

  Ok(ResultadoConfigurarPuerto { advertencia })
}

/// Bootstrap completo del backend local (spec/13 §3/§4): SQLite embebido,
/// identidades del servidor, y el bind real del puerto — todo lo que el
/// comando `puerto_backend` necesita tener resuelto ANTES de que el SPA
/// pueda hacer su primer `fetch`. Se corre a completitud dentro de
/// `.setup()` (bloqueante, vía `async_runtime::block_on`) a propósito: así
/// no hay ninguna ventana donde la ventana ya esté visible pero el comando
/// todavía devuelva un puerto sin bindear — nada que pollear ni ningún
/// evento de "backend listo" que inventar. Devuelve el listener YA
/// bindeado (se mueve tal cual al `spawn` de `axum::serve`, sin re-bindear)
/// y el puerto, para poblar el estado gestionado de Tauri.
async fn preparar_backend_local() -> anyhow::Result<(tokio::net::TcpListener, u16, axum::Router, Option<u16>)> {
  let dir = datadir();
  std::fs::create_dir_all(&dir)?;

  let pool = ellkan_backend::desktop::bootstrap_sqlite(&dir).await?;
  let server_public_key = ellkan_backend::desktop::cargar_o_generar_server_key(&pool).await?;
  let secrets_key = ellkan_backend::desktop::cargar_o_generar_secrets_key(&pool).await?;

  let estado = ellkan_backend::desktop::state::AppStateDesktop::nuevo(dir.clone(), pool, server_public_key, secrets_key);
  let router = ellkan_backend::desktop::router::construir_router_desktop(estado);

  let fijo_configurado = ellkan_backend::desktop::cargar_config(&dir).ok().and_then(|c| c.puerto_fijo);
  let (listener, puerto) = ellkan_backend::desktop::bindear_puerto(&dir).await?;
  ellkan_backend::desktop::escribir_desktop_json(puerto, env!("CARGO_PKG_VERSION"))?;

  // Si el puerto fijo estaba ocupado se usó otro sólo para esta sesión: se
  // devuelve cuál era para avisarle al usuario (F-52), no fallar en silencio.
  let puerto_ocupado = fijo_configurado.filter(|fijo| *fijo != puerto);
  Ok((listener, puerto, router, puerto_ocupado))
}

/// Busca `nombre_exe` en `%PATH%` (y en el alias de apps empaquetadas de
/// Windows, `%LOCALAPPDATA%\Microsoft\WindowsApps\`, donde vive `wt.exe`
/// cuando Windows Terminal viene de la Store en vez de un PATH clásico) —
/// sin `std::process::Command::new(nombre).spawn()` de prueba, que
/// abriría una ventana real sólo para chequear disponibilidad.
#[cfg(target_os = "windows")]
fn buscar_en_path(nombre_exe: &str) -> Option<PathBuf> {
  if let Ok(path_var) = std::env::var("PATH") {
    for dir in std::env::split_paths(&path_var) {
      let candidato = dir.join(nombre_exe);
      if candidato.is_file() {
        return Some(candidato);
      }
    }
  }
  if let Ok(local_appdata) = std::env::var("LOCALAPPDATA") {
    let alias = PathBuf::from(local_appdata).join("Microsoft").join("WindowsApps").join(nombre_exe);
    if alias.is_file() {
      return Some(alias);
    }
  }
  None
}

/// Resuelve `ellkan_askpass.exe` — se compila como binario propio del
/// crate (`src/bin/ellkan_askpass.rs`), cargo lo deja junto al ejecutable
/// principal en el mismo `target/`, así que basta con mirar al lado del
/// `.exe` en curso.
#[cfg(target_os = "windows")]
fn ruta_askpass_helper() -> anyhow::Result<PathBuf> {
  let exe_actual = std::env::current_exe()?;
  let dir = exe_actual.parent().ok_or_else(|| anyhow::anyhow!("no se pudo resolver el directorio del ejecutable"))?;
  let candidato = dir.join("ellkan_askpass.exe");
  if !candidato.is_file() {
    anyhow::bail!("no se encontró ellkan_askpass.exe junto a {}", exe_actual.display());
  }
  Ok(candidato)
}

/// Arma el `Command` para lanzar `programa args..` dentro de Windows
/// Terminal si está disponible, o en una consola nueva propia si no —
/// mismo criterio en las 4 ramas de `conectar_recurso` (sin esto, `ssh`/
/// `ftp`/`telnet` heredarían la consola de este proceso, que no es una
/// terminal interactiva real). Nunca pasa por `cmd /c`/`powershell -Command`
/// (evita el mismo tipo de bug de inyección que `ellkan_askpass.exe` evita
/// del lado del secreto, pero acá con `host`/`usuario` — datos que sí puede
/// traer un import CSV/KDBX externo, F-27): cada valor es un argumento de
/// `Command` separado, sin intérprete de shell de por medio.
#[cfg(target_os = "windows")]
fn comando_en_terminal(programa: &Path, args: &[String]) -> std::process::Command {
  if let Some(wt) = buscar_en_path("wt.exe") {
    // `--` le dice a `wt` que todo lo que sigue es el programa+argumentos a
    // ejecutar tal cual, no opciones propias de `wt`.
    let mut c = std::process::Command::new(wt);
    c.arg("--").arg(programa);
    c.args(args);
    c
  } else {
    let mut c = std::process::Command::new(programa);
    c.args(args);
    use std::os::windows::process::CommandExt;
    const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
    c.creation_flags(CREATE_NEW_CONSOLE);
    c
  }
}

/// "Conectar" desde la GUI (F-49, spec/13 §9). Qué se lanza y cómo se entrega
/// el secreto lo decide `ellkan_backend::desktop::conectar::planificar` (que
/// además valida `host`/`usuario`, datos que pueden venir de un import
/// externo): acá sólo se ejecuta el plan.
///
/// El secreto NUNCA va en la línea de comandos ni en el historial:
/// - `ssh`: `SSH_ASKPASS` (protocolo estándar, ver `ellkan_askpass`).
/// - `psql`/`mysql`: variable de entorno del proceso hijo (`PGPASSWORD`/`MYSQL_PWD`).
/// - `rdp`: credencial `TERMSRV/<host>` de Windows con persistencia de sesión,
///   borrada a los pocos segundos.
/// - `ftp`/`telnet`/`vnc`/`mongosh`: sin mecanismo equivalente (el login ocurre
///   dentro de la sesión o en un diálogo propio). Sin inventar un inyector de
///   teclas (el mismo anti-patrón que spec/13 §11bis rechaza para Wayland), el
///   frontend deja el secreto en el portapapeles con auto-limpieza ANTES de
///   llamar acá; el parámetro `secreto` no se usa para estos tipos.
#[cfg(target_os = "windows")]
#[tauri::command]
fn conectar_recurso(tipo: String, usuario: Option<String>, host: String, puerto: u16, secreto: String) -> Result<(), String> {
  use ellkan_backend::desktop::conectar::{planificar, Inyeccion, Ventana};

  let secreto = Zeroizing::new(secreto);
  let plan = planificar(&tipo, usuario.as_deref(), &host, puerto)?;
  let programa = plan.programas.iter().find_map(|nombre| buscar_en_path(nombre)).ok_or_else(|| plan.falta.to_string())?;

  let mut comando = match plan.ventana {
    Ventana::Terminal => comando_en_terminal(&programa, &plan.args),
    Ventana::Propia => {
      let mut c = std::process::Command::new(&programa);
      c.args(&plan.args);
      c
    }
  };

  let mut credencial_rdp = false;
  match plan.inyeccion {
    Inyeccion::Askpass => {
      let askpass = ruta_askpass_helper()
        .map_err(|e| format!("no se pudo preparar la conexión asistida ({e:#}) — copiá el comando y pegá la contraseña a mano"))?;
      comando.env("SSH_ASKPASS_REQUIRE", "force");
      comando.env("SSH_ASKPASS", &askpass);
      comando.env("ELLKAN_ASKPASS_SECRET", secreto.as_str());
    }
    Inyeccion::Entorno(variable) => {
      comando.env(variable, secreto.as_str());
    }
    Inyeccion::CredencialRdp => {
      sistema::guardar_credencial_rdp(&host, puerto, usuario.as_deref().unwrap_or(""), secreto.as_str())?;
      credencial_rdp = true;
    }
    Inyeccion::Portapapeles => {}
  }

  let resultado = comando.spawn().map(|_| ()).map_err(|e| format!("no se pudo lanzar {}: {e:#}", programa.display()));

  if credencial_rdp {
    // `mstsc` lee la credencial al abrir la conexión: no hace falta que siga
    // ahí. Si no se pudo lanzar, se borra de inmediato.
    if resultado.is_err() {
      sistema::borrar_credencial_rdp(&host, puerto);
    } else {
      std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(20));
        sistema::borrar_credencial_rdp(&host, puerto);
      });
    }
  }
  resultado
}

#[cfg(not(target_os = "windows"))]
#[tauri::command]
fn conectar_recurso(tipo: String, usuario: Option<String>, host: String, puerto: u16, secreto: String) -> Result<(), String> {
  let _ = (tipo, usuario, host, puerto, secreto);
  Err("Conectar (F-49) todavía sólo está implementado en Windows".to_string())
}

/// F-50: Guarda una clave de envoltura cifrada (wrapped key) en el almacén de credenciales seguro del SO.
/// Nunca almacena la contraseña ni la clave privada en claro (criterio de seguridad H-01).
#[tauri::command]
fn guardar_envoltura_llavero(vault_id: String, envoltura_b64: String) -> Result<(), String> {
  let entry = keyring::Entry::new("Ellkan", &format!("vault_{vault_id}"))
    .map_err(|e| format!("Error inicializando llavero del SO: {e}"))?;
  entry
    .set_password(&envoltura_b64)
    .map_err(|e| format!("Error guardando en el llavero del SO: {e}"))?;
  Ok(())
}

/// F-50: Recupera la clave de envoltura cifrada desde el almacén de credenciales del SO.
#[tauri::command]
fn recuperar_envoltura_llavero(vault_id: String) -> Result<Option<String>, String> {
  let entry = keyring::Entry::new("Ellkan", &format!("vault_{vault_id}"))
    .map_err(|e| format!("Error inicializando llavero del SO: {e}"))?;
  match entry.get_password() {
    Ok(pwd) => Ok(Some(pwd)),
    Err(keyring::Error::NoEntry) => Ok(None),
    Err(e) => Err(format!("Error leyendo del llavero del SO: {e}")),
  }
}

/// F-50: Elimina la clave de envoltura del almacén de credenciales del SO al desactivar biometría o cerrar sesión.
#[tauri::command]
fn eliminar_envoltura_llavero(vault_id: String) -> Result<(), String> {
  let entry = keyring::Entry::new("Ellkan", &format!("vault_{vault_id}"))
    .map_err(|e| format!("Error inicializando llavero del SO: {e}"))?;
  match entry.delete_credential() {
    Ok(_) | Err(keyring::Error::NoEntry) => Ok(()),
    Err(e) => Err(format!("Error eliminando del llavero del SO: {e}")),
  }
}

// ---------------------------------------------------------------------------
// Punto 9: instalar la extensión de navegador desde la app. La extensión
// viaja embebida en este ejecutable (`build.rs` → `extension-bundle/`); la
// lógica de extraer/versionar vive en `ellkan_backend::desktop::extension`
// (probada sin Tauri). Acá sólo están los comandos que el SPA llama y el
// refresco de cada arranque.
// ---------------------------------------------------------------------------

mod bundle_extension {
  include!(concat!(env!("OUT_DIR"), "/extension_bundle.rs"));
}

use ellkan_backend::desktop::extension::{self as ext, ArchivoExtension};

fn archivos_de(objetivo: &str) -> Vec<ArchivoExtension<'static>> {
  bundle_extension::BUNDLE
    .iter()
    .filter(|(o, _, _)| *o == objetivo)
    .map(|(_, ruta, contenido)| ArchivoExtension { ruta, contenido })
    .collect()
}

/// Carpeta estable donde queda la extensión ya extraída — la que el usuario
/// apunta UNA vez en "Cargar descomprimida" y que la app mantiene al día.
/// Vive en Documentos ("Ellkan extensión"), donde ese diálogo abre por
/// defecto; ver `ellkan_backend::desktop::extension::carpeta_de_instalacion`.
fn carpeta_extension(objetivo: &str) -> PathBuf {
  ext::carpeta_de_instalacion(objetivo)
}

#[derive(serde::Serialize)]
struct NavegadorExtension {
  id: String,
  objetivo: String,
  /// El navegador está instalado en esta PC — sólo se ofrecen los que sí.
  instalado: bool,
  elegido: bool,
  ruta: String,
  version_instalada: Option<String>,
  al_dia: bool,
}

#[derive(serde::Serialize)]
struct EstadoExtension {
  /// `false` en un build que no preparó la extensión (desarrollo).
  incluida: bool,
  version_incluida: Option<String>,
  navegadores: Vec<NavegadorExtension>,
}

fn navegador_extension(id: &str, objetivo: &str, elegidos: &[String]) -> NavegadorExtension {
  let carpeta = carpeta_extension(objetivo);
  NavegadorExtension {
    id: id.to_string(),
    objetivo: objetivo.to_string(),
    instalado: ext::buscar_ejecutable(id).is_some(),
    elegido: elegidos.iter().any(|n| n == id),
    ruta: carpeta.to_string_lossy().into_owned(),
    version_instalada: ext::version_instalada(&carpeta),
    al_dia: ext::esta_al_dia(&carpeta, &archivos_de(objetivo)),
  }
}

#[tauri::command]
fn extension_estado() -> Result<EstadoExtension, String> {
  let config = ellkan_backend::desktop::cargar_config(&datadir()).map_err(|e| format!("no se pudo leer la configuración: {e:#}"))?;
  let navegadores =
    ext::NAVEGADORES.iter().map(|(id, objetivo)| navegador_extension(id, objetivo, &config.extension_navegadores)).collect();
  let chromium = archivos_de("chromium");
  Ok(EstadoExtension { incluida: !chromium.is_empty(), version_incluida: ext::version_incluida(&chromium), navegadores })
}

/// Extrae (o actualiza) la extensión para `navegador` y lo recuerda: desde
/// ese momento la app la mantiene al día en cada arranque.
#[tauri::command]
fn extension_instalar(app: tauri::AppHandle, navegador: String) -> Result<NavegadorExtension, String> {
  let objetivo = ext::objetivo_de(&navegador).ok_or_else(|| format!("navegador no soportado: {navegador}"))?;
  let carpeta = carpeta_extension(objetivo);
  ext::instalar(&carpeta, &archivos_de(objetivo)).map_err(|e| format!("{e:#}"))?;
  // La extensión trae la dirección de esta app puesta: el usuario no tiene
  // por qué saber en qué puerto escucha el backend local.
  if let Some(puerto) = app.try_state::<PuertoBackend>() {
    ext::escribir_conexion(&carpeta, puerto.0).map_err(|e| format!("{e:#}"))?;
  }

  let dir = datadir();
  let mut config = ellkan_backend::desktop::cargar_config(&dir).map_err(|e| format!("no se pudo leer la configuración: {e:#}"))?;
  if !config.extension_navegadores.iter().any(|n| n == &navegador) {
    config.extension_navegadores.push(navegador.clone());
    ellkan_backend::desktop::guardar_config(&dir, &config).map_err(|e| format!("no se pudo guardar la configuración: {e:#}"))?;
  }
  Ok(navegador_extension(&navegador, objetivo, &config.extension_navegadores))
}

/// Qué hace la app al cerrar la ventana (preferencia guardada).
#[tauri::command]
fn al_cerrar_configurado() -> Result<ellkan_backend::desktop::AlCerrar, String> {
  ellkan_backend::desktop::cargar_config(&datadir())
    .map(|c| c.al_cerrar)
    .map_err(|e| format!("no se pudo leer la configuración: {e:#}"))
}

#[tauri::command]
fn configurar_al_cerrar(modo: ellkan_backend::desktop::AlCerrar) -> Result<(), String> {
  let dir = datadir();
  let mut config = ellkan_backend::desktop::cargar_config(&dir).map_err(|e| format!("no se pudo leer la configuración: {e:#}"))?;
  config.al_cerrar = modo;
  ellkan_backend::desktop::guardar_config(&dir, &config).map_err(|e| format!("no se pudo guardar la configuración: {e:#}"))
}

/// Cierra la app del todo — lo mismo que "Salir" del menú de la bandeja.
#[tauri::command]
fn cerrar_aplicacion(app: tauri::AppHandle) {
  app.exit(0);
}

/// Oculta la ventana y deja la app corriendo en la bandeja del sistema.
#[tauri::command]
fn ocultar_a_bandeja(ventana: tauri::WebviewWindow) {
  let _ = ventana.hide();
  avisar_en_bandeja(ventana.app_handle());
}

const AVISO: &str = "aviso";
const AVISO_SEGUNDOS: u64 = 8;

/// Aviso en una ventanita sin bordes en la esquina de la pantalla (junto a
/// la bandeja), que se va sola. `datos` lo lee `static/aviso.html` como
/// `window.__AVISO__`: `{ "tipo": "bandeja" }`, `{ "tipo": "puerto", … }`.
///
/// No es una notificación del sistema a propósito: un `.exe` portable sin
/// instalar no tiene un identificador de aplicación registrado en Windows y
/// sus notificaciones toast pueden no mostrarse, sin ningún error.
fn mostrar_aviso(app: &tauri::AppHandle, datos: serde_json::Value) {
  if app.get_webview_window(AVISO).is_some() {
    return;
  }
  let app = app.clone();
  // Crear una ventana desde el hilo del bucle de eventos (donde corre el
  // manejador de cierre) puede bloquear la app en Windows: va en otro hilo.
  std::thread::spawn(move || {
    let (ancho, alto, margen) = (360.0, 92.0, 12.0);
    let mut ventana = tauri::WebviewWindowBuilder::new(&app, AVISO, tauri::WebviewUrl::App("aviso.html".into()))
      .title("Ellkan")
      .initialization_script(format!("window.__AVISO__ = {datos};"))
      .inner_size(ancho, alto)
      .decorations(false)
      .resizable(false)
      .always_on_top(true)
      .skip_taskbar(true)
      .focused(false)
      .shadow(true);
    // Esquina inferior derecha del área útil (sin la barra de tareas).
    if let Ok(Some(monitor)) = app.primary_monitor() {
      let escala = monitor.scale_factor();
      let area = monitor.work_area();
      let x = (f64::from(area.position.x) + f64::from(area.size.width)) / escala - ancho - margen;
      let y = (f64::from(area.position.y) + f64::from(area.size.height)) / escala - alto - margen;
      ventana = ventana.position(x, y);
    }
    match ventana.build() {
      Ok(aviso) => {
        std::thread::sleep(std::time::Duration::from_secs(AVISO_SEGUNDOS));
        let _ = aviso.destroy();
      }
      Err(e) => log::warn!("no se pudo mostrar el aviso: {e}"),
    }
  });
}

/// Al esconder la ventana, la app "desaparece" pero el proceso sigue: sin
/// aviso el usuario cree que la cerró (pasó).
fn avisar_en_bandeja(app: &tauri::AppHandle) {
  mostrar_aviso(app, serde_json::json!({ "tipo": "bandeja" }));
}

/// El usuario tocó el aviso: se descarta sin esperar a que se vaya solo.
#[tauri::command]
async fn cerrar_aviso(app: tauri::AppHandle) {
  if let Some(aviso) = app.get_webview_window(AVISO) {
    let _ = aviso.destroy();
  }
}

#[derive(serde::Serialize)]
struct InfoApp {
  version: String,
  /// Fecha (segundos Unix) del ejecutable que está corriendo — la de su
  /// compilación o copia. Sirve para saber a simple vista QUÉ build se está
  /// viendo: la app es de instancia única y cerrar la ventana la manda a la
  /// bandeja, así que abrir el `.exe` de nuevo puede enfocar una instancia
  /// vieja sin avisar (pasó probando el build nuevo).
  binario_unix: Option<u64>,
  ruta: String,
}

#[tauri::command]
fn info_app() -> InfoApp {
  let exe = std::env::current_exe().ok();
  let binario_unix = exe
    .as_ref()
    .and_then(|ruta| std::fs::metadata(ruta).ok())
    .and_then(|meta| meta.modified().ok())
    .and_then(|fecha| fecha.duration_since(std::time::UNIX_EPOCH).ok())
    .map(|d| d.as_secs());
  InfoApp {
    version: env!("CARGO_PKG_VERSION").to_string(),
    binario_unix,
    ruta: exe.map(|r| r.to_string_lossy().into_owned()).unwrap_or_default(),
  }
}

/// Abre `navegador` directamente en su página de extensiones. Es lo que evita
/// que el usuario tenga que pegar `chrome://extensions` a mano: los
/// navegadores no permiten abrir esas direcciones desde otra app por el
/// camino común, pero sí aceptan la URL como argumento de su propio
/// ejecutable.
#[tauri::command]
fn extension_abrir_navegador(navegador: String) -> Result<(), String> {
  ext::abrir_pagina_de_extensiones(&navegador).map_err(|e| format!("{e:#}"))
}

/// Guarda en la carpeta Descargas un archivo que la ventana "descarga". El
/// webview de Tauri no procesa un `<a download>` sobre un blob (el clic no
/// hace nada), así que el guardado lo hace el backend. El contenido llega en
/// base64 porque es lo que cruza el IPC sin inflarse. Nunca pisa un archivo
/// existente y el nombre se sanea (ver `ellkan_backend::desktop::descargas`).
#[tauri::command]
fn guardar_descarga(nombre: String, contenido_b64: String) -> Result<String, String> {
  let bytes = ellkan_backend::b64::decode(&contenido_b64).map_err(|e| format!("contenido inválido: {e}"))?;
  let carpeta = ellkan_backend::desktop::descargas::carpeta_descargas().map_err(|e| format!("{e:#}"))?;
  let ruta = ellkan_backend::desktop::descargas::guardar_sin_pisar(&carpeta, &nombre, &bytes).map_err(|e| format!("{e:#}"))?;
  Ok(ruta.to_string_lossy().into_owned())
}

/// Deja de mantener al día la extensión para `navegador`. No borra la carpeta
/// (el navegador puede seguir teniéndola cargada, y otros navegadores
/// Chromium comparten la misma).
#[tauri::command]
fn extension_dejar_de_actualizar(navegador: String) -> Result<(), String> {
  let dir = datadir();
  let mut config = ellkan_backend::desktop::cargar_config(&dir).map_err(|e| format!("no se pudo leer la configuración: {e:#}"))?;
  config.extension_navegadores.retain(|n| n != &navegador);
  ellkan_backend::desktop::guardar_config(&dir, &config).map_err(|e| format!("no se pudo guardar la configuración: {e:#}"))
}

/// En cada arranque: para cada navegador que el usuario eligió, si la carpeta
/// no está al día con la extensión que trae ESTA build (porque la app se
/// actualizó, o porque alguien borró la carpeta), se vuelve a extraer. Es lo
/// que hace que la extensión "quede para siempre" y se actualice sola con la
/// app. También deja al día la dirección del backend local (`puerto`), que
/// puede cambiar entre arranques si el puerto elegido estaba ocupado.
/// Nunca falla el arranque: sólo deja un aviso en el log.
fn refrescar_extensiones_elegidas(puerto: u16) {
  let Ok(config) = ellkan_backend::desktop::cargar_config(&datadir()) else { return };
  let mut ya_hechos: Vec<&str> = Vec::new();
  for navegador in &config.extension_navegadores {
    let Some(objetivo) = ext::objetivo_de(navegador) else { continue };
    // Chrome/Edge/Brave/Opera comparten carpeta: se refresca una sola vez.
    if ya_hechos.contains(&objetivo) {
      continue;
    }
    ya_hechos.push(objetivo);

    let archivos = archivos_de(objetivo);
    let carpeta = carpeta_extension(objetivo);
    if archivos.is_empty() {
      continue;
    }
    if !ext::esta_al_dia(&carpeta, &archivos) {
      match ext::instalar(&carpeta, &archivos) {
        Ok(()) => log::info!("extensión de navegador actualizada en {}", carpeta.display()),
        Err(e) => {
          log::warn!("no se pudo actualizar la extensión en {}: {e:#}", carpeta.display());
          continue;
        }
      }
    }
    if let Err(e) = ext::escribir_conexion(&carpeta, puerto) {
      log::warn!("no se pudo dejar la dirección del backend en {}: {e:#}", carpeta.display());
    }
  }
}

// ---------------------------------------------------------------------------
// Integración con Windows: inicio con la sesión, enlaces `ellkan://`, bloqueo
// al bloquear la pantalla y modo portable. La lógica de sistema vive en
// `sistema.rs`/`portable.rs`; acá están los comandos que llama Ajustes.
// ---------------------------------------------------------------------------

/// Ruta interna a la que hay que navegar por un enlace `ellkan://` recibido
/// (al arrancar o desde una segunda instancia). El frontend la consume al
/// cargar y cuando llega el evento `enlace-profundo`.
#[derive(Default)]
struct EnlacePendiente(std::sync::Mutex<Option<String>>);

#[tauri::command]
fn enlace_pendiente(estado: tauri::State<EnlacePendiente>) -> Option<String> {
  estado.0.lock().ok().and_then(|mut pendiente| pendiente.take())
}

/// Busca un enlace `ellkan://…` entre los argumentos y, si es válido, lo deja
/// como pendiente y avisa a la ventana. Los argumentos vienen de afuera: sólo
/// cuenta lo que `enlaces::interpretar` acepta.
fn procesar_argumentos(app: &tauri::AppHandle, args: &[String]) -> bool {
  let Some(ruta) = args.iter().find_map(|a| ellkan_backend::desktop::enlaces::interpretar(a)) else {
    return false;
  };
  if let Some(pendiente) = app.try_state::<EnlacePendiente>()
    && let Ok(mut guardado) = pendiente.0.lock()
  {
    *guardado = Some(ruta);
  }
  if let Some(ventana) = app.get_webview_window("main") {
    let _ = ventana.emit("enlace-profundo", ());
  }
  true
}

#[derive(serde::Serialize)]
struct EstadoSistema {
  /// `false` fuera de Windows: inicio con la sesión, enlaces y bloqueo de pantalla no aplican.
  soportado: bool,
  autostart: bool,
  enlaces: bool,
  bloquear_con_pantalla: bool,
  portable: bool,
  carpeta_de_datos: String,
}

#[tauri::command]
fn sistema_estado() -> Result<EstadoSistema, String> {
  let config = ellkan_backend::desktop::cargar_config(&datadir()).map_err(|e| format!("no se pudo leer la configuración: {e:#}"))?;
  Ok(EstadoSistema {
    soportado: cfg!(windows),
    autostart: sistema::autostart_activo(),
    enlaces: sistema::enlaces_activos(),
    bloquear_con_pantalla: config.bloquear_con_pantalla_efectivo(),
    portable: portable::activo(),
    carpeta_de_datos: datadir().to_string_lossy().into_owned(),
  })
}

#[tauri::command]
fn configurar_autostart(activo: bool) -> Result<(), String> {
  sistema::configurar_autostart(activo)
}

#[tauri::command]
fn configurar_enlaces(activo: bool) -> Result<(), String> {
  sistema::configurar_enlaces(activo)
}

#[tauri::command]
fn configurar_bloqueo_pantalla(activo: bool) -> Result<(), String> {
  let dir = datadir();
  let mut config = ellkan_backend::desktop::cargar_config(&dir).map_err(|e| format!("no se pudo leer la configuración: {e:#}"))?;
  config.bloquear_con_pantalla = Some(activo);
  ellkan_backend::desktop::guardar_config(&dir, &config).map_err(|e| format!("no se pudo guardar la configuración: {e:#}"))
}

/// Pide a Windows que avise cuando se bloquea la pantalla y, en ese momento,
/// bloquea la bóveda (F-52). El evento `bloquear-boveda` es el mismo que
/// dispara "Bloquear bóveda" en la bandeja. Sólo Windows.
#[cfg(windows)]
fn vigilar_bloqueo_de_pantalla(app: &tauri::AppHandle) {
  let Some(ventana) = app.get_webview_window("main") else { return };
  let Ok(hwnd) = ventana.hwnd() else { return };
  let app = app.clone();
  let resultado = sistema::vigilar_bloqueo(hwnd, move || {
    let activo = ellkan_backend::desktop::cargar_config(&datadir()).map(|c| c.bloquear_con_pantalla_efectivo()).unwrap_or(true);
    if activo && let Some(ventana) = app.get_webview_window("main") {
      let _ = ventana.emit("bloquear-boveda", ());
    }
  });
  if let Err(e) = resultado {
    log::warn!("{e}");
  }
}

#[cfg(not(windows))]
fn vigilar_bloqueo_de_pantalla(_app: &tauri::AppHandle) {}

/// Simula el aviso de "la pantalla se bloqueó" de Windows, para probar de
/// punta a punta que la bóveda se bloquea sin bloquear la sesión del usuario.
#[cfg(windows)]
#[tauri::command]
fn simular_bloqueo_de_pantalla(ventana: tauri::WebviewWindow) {
  if let Ok(hwnd) = ventana.hwnd() {
    sistema::simular_bloqueo(hwnd);
  }
}

#[cfg(not(windows))]
#[tauri::command]
fn simular_bloqueo_de_pantalla() {}

use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::Emitter;
use tauri_plugin_global_shortcut::{Code, GlobalShortcutExt, Modifiers, Shortcut, ShortcutState};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
  // Lo llama el desinstalador antes de borrar los archivos: limpia el registro y sale, sin abrir nada.
  if std::env::args().any(|a| a == sistema::ARG_LIMPIAR) {
    sistema::limpiar();
    let args: Vec<String> = std::env::args().collect();
    let borrar = args.iter().any(|a| a == sistema::ARG_BORRAR_DATOS)
      || (args.iter().any(|a| a == sistema::ARG_PREGUNTAR_DATOS) && sistema::preguntar_borrar_datos());
    if borrar {
      borrar_datos_del_usuario();
    }
    return;
  }

  // Modo portable: redirige lo que vive fuera del datadir. Primero de todo.
  portable::preparar();

  tauri::Builder::default()
    .manage(EnlacePendiente::default())
    // F-45/F-54 (instancia única) — DEBE ser el primer plugin registrado,
    // requisito documentado de `tauri-plugin-single-instance`: si un
    // segundo proceso arranca mientras éste ya está corriendo, el segundo
    // se cierra solo y este callback corre en el primero, enfocando la
    // ventana existente en vez de dejar dos procesos compitiendo por el
    // mismo puerto fijo — la causa real de la inestabilidad encontrada
    // 2026-09-17 (ver comentario en `Cargo.toml`).
    .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
      if let Some(ventana) = app.get_webview_window("main") {
        let _ = ventana.show();
        let _ = ventana.unminimize();
        let _ = ventana.set_focus();
      }
      // Un enlace `ellkan://…` abierto desde afuera llega como argumento de
      // esta segunda instancia.
      procesar_argumentos(app, &args);
    }))
    // Sin esto, un `<a target="_blank">` (ej. la URI de un recurso en el
    // panel de detalle del Vault) no hace nada — el WebView no tiene forma
    // de abrir el navegador del sistema por sí solo. El plugin intercepta
    // esos clics y los manda al navegador default del SO.
    .plugin(tauri_plugin_opener::init())
    .invoke_handler(tauri::generate_handler![
      puerto_backend,
      puerto_configurado,
      configurar_puerto_fijo,
      conectar_recurso,
      guardar_envoltura_llavero,
      recuperar_envoltura_llavero,
      eliminar_envoltura_llavero,
      extension_estado,
      extension_instalar,
      extension_abrir_navegador,
      extension_dejar_de_actualizar,
      guardar_descarga,
      info_app,
      al_cerrar_configurado,
      configurar_al_cerrar,
      cerrar_aplicacion,
      ocultar_a_bandeja,
      cerrar_aviso,
      sistema_estado,
      configurar_autostart,
      configurar_enlaces,
      configurar_bloqueo_pantalla,
      enlace_pendiente,
      simular_bloqueo_de_pantalla
    ])
    // F-45: qué hace la "X" depende de la preferencia del usuario (`AlCerrar`).
    // Antes SIEMPRE ocultaba a la bandeja sin avisar: el usuario "cerraba" la
    // app, seguía corriendo, y al abrir el `.exe` de nuevo (la app es de
    // instancia única) volvía a ver la ventana vieja. Ahora, por defecto, se
    // le pregunta.
    .on_window_event(|window, event| {
      if let tauri::WindowEvent::CloseRequested { api, .. } = event {
        // Sólo la ventana principal: el aviso de la bandeja es otra ventana.
        if window.label() != "main" {
          return;
        }
        // Una ventana que YA está oculta en la bandeja sólo recibe un cierre
        // si viene del sistema (apagado, cerrar sesión de Windows): dejarlo
        // pasar, si no la app bloquearía el apagado.
        if !window.is_visible().unwrap_or(true) {
          return;
        }
        match ellkan_backend::desktop::cargar_config(&datadir()).map(|c| c.al_cerrar).unwrap_or_default() {
          // Se cierra la ventana y, siendo la única, termina la app.
          ellkan_backend::desktop::AlCerrar::Salir => {}
          ellkan_backend::desktop::AlCerrar::Bandeja => {
            api.prevent_close();
            let _ = window.hide();
            avisar_en_bandeja(window.app_handle());
          }
          ellkan_backend::desktop::AlCerrar::Preguntar => {
            api.prevent_close();
            let _ = window.emit("cierre-solicitado", ());
          }
        }
      }
    })
    .setup(|app| {
      // Log a archivo (`Ellkan.log` en la carpeta de logs de la app), con
      // rotación. En debug también va a la salida estándar, con más detalle;
      // en release sólo avisos y errores (no hay consola) para que haya con
      // qué diagnosticar sin llenar el disco ni registrar de más.
      let mut registro = tauri_plugin_log::Builder::default()
        .max_file_size(2_000_000)
        .rotation_strategy(tauri_plugin_log::RotationStrategy::KeepSome(3));
      registro = if cfg!(debug_assertions) {
        registro.level(log::LevelFilter::Info)
      } else {
        registro
          .level(log::LevelFilter::Warn)
          .clear_targets()
          .target(tauri_plugin_log::Target::new(tauri_plugin_log::TargetKind::LogDir { file_name: None }))
      };
      app.handle().plugin(registro.build())?;

      // F-51: Atajo global de teclado (Ctrl+Shift+Espacio) para invocar acceso rápido
      let atajo = Shortcut::new(Some(Modifiers::CONTROL | Modifiers::SHIFT), Code::Space);
      app.handle().plugin(
        tauri_plugin_global_shortcut::Builder::new()
          .with_handler(move |app, shortcut_pressed, event| {
            if shortcut_pressed == &atajo
              && event.state() == ShortcutState::Pressed
              && let Some(ventana) = app.get_webview_window("main")
            {
              if ventana.is_visible().unwrap_or(false) && ventana.is_focused().unwrap_or(false) {
                let _ = ventana.hide();
              } else {
                let _ = ventana.show();
                let _ = ventana.unminimize();
                let _ = ventana.set_focus();
                let _ = ventana.emit("atajo-global-activado", ());
              }
            }
          })
          .build(),
      )?;
      let _ = app.global_shortcut().register(atajo);

      // F-45: Bandeja del sistema (System Tray) con menú contextual
      let abrir_item = MenuItem::with_id(app, "abrir", "Abrir Ellkan", true, None::<&str>)?;
      let bloquear_item = MenuItem::with_id(app, "bloquear", "Bloquear Bóveda", true, None::<&str>)?;
      let salir_item = MenuItem::with_id(app, "salir", "Salir", true, None::<&str>)?;
      let menu_tray = Menu::with_items(app, &[&abrir_item, &bloquear_item, &salir_item])?;

      if let Some(icon) = app.default_window_icon().cloned() {
        let _tray = TrayIconBuilder::new()
          .icon(icon)
          .tooltip("Ellkan Password Manager")
          .menu(&menu_tray)
          .show_menu_on_left_click(false)
          .on_menu_event(|app, event| {
            match event.id.as_ref() {
              "abrir" => {
                if let Some(ventana) = app.get_webview_window("main") {
                  let _ = ventana.show();
                  let _ = ventana.unminimize();
                  let _ = ventana.set_focus();
                }
              }
              "bloquear" => {
                if let Some(ventana) = app.get_webview_window("main") {
                  let _ = ventana.emit("bloquear-boveda", ());
                  let _ = ventana.show();
                  let _ = ventana.set_focus();
                }
              }
              "salir" => {
                app.exit(0);
              }
              _ => {}
            }
          })
          .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
              button: MouseButton::Left,
              button_state: MouseButtonState::Up,
              ..
            } = event
            {
              let app = tray.app_handle();
              if let Some(ventana) = app.get_webview_window("main") {
                if ventana.is_visible().unwrap_or(false) {
                  let _ = ventana.hide();
                } else {
                  let _ = ventana.show();
                  let _ = ventana.unminimize();
                  let _ = ventana.set_focus();
                }
              }
            }
          })
          .build(app)?;
      }

      match tauri::async_runtime::block_on(preparar_backend_local()) {
        Ok((listener, puerto, router, puerto_ocupado)) => {
          app.manage(PuertoBackend(puerto));
          if let Some(esperado) = puerto_ocupado {
            log::warn!("el puerto fijo {esperado} estaba ocupado: se usa el {puerto} sólo en esta sesión");
            mostrar_aviso(app.handle(), serde_json::json!({ "tipo": "puerto", "esperado": esperado, "actual": puerto }));
          }
          // Punto 9: si la app se actualizó, las extensiones de navegador que
          // el usuario ya instaló desde acá se actualizan con ella, y llevan
          // la dirección de este backend. Va después de bindear el puerto y
          // en un hilo aparte: son unos pocos archivos, no hay por qué
          // demorar la ventana.
          std::thread::spawn(move || refrescar_extensiones_elegidas(puerto));
          tauri::async_runtime::spawn(async move {
            log::info!("backend local de Ellkan escuchando en 127.0.0.1:{puerto}");
            if let Err(e) = axum::serve(listener, router).await {
              log::error!("el backend local terminó con error: {e:#}");
            }
          });
        }
        // Sin backend, la ventana igual se abre (mismo criterio que antes:
        // nunca tirar abajo la app entera por esto) pero `puerto_backend`
        // no tiene estado gestionado — el SPA lo ve como un 404/timeout de
        // `invoke`, visible en los logs de abajo para diagnosticar.
        Err(e) => log::error!("no se pudo preparar el backend local: {e:#}"),
      }

      // Argumentos de arranque: un enlace `ellkan://…` (la app se abrió por
      // él) o `--minimizado` (arranque con la sesión de Windows: sin abrir la
      // ventana, sólo la bandeja). Un enlace siempre trae la ventana al frente.
      let args: Vec<String> = std::env::args().collect();
      let por_enlace = procesar_argumentos(app.handle(), &args);
      if !por_enlace
        && args.iter().any(|a| a == sistema::ARG_MINIMIZADO)
        && let Some(ventana) = app.get_webview_window("main")
      {
        let _ = ventana.hide();
      }

      vigilar_bloqueo_de_pantalla(app.handle());

      Ok(())
    })
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}

// El desbloqueo rápido con el llavero de Windows (F-50) usa estos tres comandos. Se probó
// que nada se guardaba: `keyring` estaba compilado sin el almacén nativo, así que usaba
// uno de prueba en memoria. Esta prueba lo ejerce contra el Administrador de credenciales
// real, con un id propio que limpia al terminar.
#[cfg(all(test, windows))]
mod pruebas_llavero {
  use super::{eliminar_envoltura_llavero, guardar_envoltura_llavero, recuperar_envoltura_llavero};

  #[test]
  fn la_clave_de_envoltura_se_guarda_se_recupera_y_se_borra_de_verdad() {
    let id = format!("prueba-{}", std::process::id());
    assert_eq!(recuperar_envoltura_llavero(id.clone()).unwrap(), None, "al principio no hay nada");

    guardar_envoltura_llavero(id.clone(), "envoltura-de-prueba".into()).unwrap();
    assert_eq!(
      recuperar_envoltura_llavero(id.clone()).unwrap().as_deref(),
      Some("envoltura-de-prueba"),
      "se lee de nuevo desde una entrada distinta: quedó guardada en el llavero, no en memoria"
    );

    eliminar_envoltura_llavero(id.clone()).unwrap();
    assert_eq!(recuperar_envoltura_llavero(id.clone()).unwrap(), None, "borrada");
    eliminar_envoltura_llavero(id).unwrap(); // borrar lo que no existe no falla
  }
}
