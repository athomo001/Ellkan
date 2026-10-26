// Autor: Athan Espinoza

use std::path::PathBuf;

use tauri::Manager;
use zeroize::Zeroizing;

#[cfg(windows)]
mod canal_extension;
mod portable;
mod sistema;
#[cfg(windows)]
#[doc(hidden)]
pub mod tuberia;

/// Versión de la app: la de `tauri.conf.json` (la misma del instalador MSI), no la del
/// `Cargo.toml`. La exporta `build.rs`.
const VERSION_APP: &str = env!("ELLKAN_VERSION");

/// Handle de la app para avisos que nacen fuera de la ventana (cambios de la
/// extensión); se fija en `setup`.
static APP: std::sync::OnceLock<tauri::AppHandle> = std::sync::OnceLock::new();

/// Cambios de la extensión que la interfaz todavía no recogió
/// (`<datadir>/cambios-extension.json`, `{id: "subir" | "borrar"}`). Sólo ids,
/// nunca datos. Sobrevive a la bóveda bloqueada y a cerrar la app: la interfaz
/// lo vacía al empezar cada sync (`tomar_cambios_extension`).
static CAMBIOS_EXTENSION: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn archivo_cambios_extension() -> PathBuf {
  datadir().join("cambios-extension.json")
}

fn leer_cambios_extension() -> serde_json::Map<String, serde_json::Value> {
  std::fs::read(archivo_cambios_extension())
    .ok()
    .and_then(|b| serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(&b).ok())
    .unwrap_or_default()
}

fn anotar_cambio_de_extension(id: &str, operacion: &str) {
  let _guardia = CAMBIOS_EXTENSION.lock().unwrap_or_else(|e| e.into_inner());
  let mut cambios = leer_cambios_extension();
  cambios.insert(id.to_string(), serde_json::Value::String(operacion.to_string()));
  if let Err(e) = std::fs::write(archivo_cambios_extension(), serde_json::Value::Object(cambios).to_string()) {
    log::warn!("no se pudo anotar el cambio de la extensión {id}: {e}");
  }
}

/// Devuelve y borra los cambios de la extensión pendientes de subir.
#[tauri::command]
fn tomar_cambios_extension() -> serde_json::Map<String, serde_json::Value> {
  let _guardia = CAMBIOS_EXTENSION.lock().unwrap_or_else(|e| e.into_inner());
  let cambios = leer_cambios_extension();
  if !cambios.is_empty() {
    let _ = std::fs::remove_file(archivo_cambios_extension());
  }
  cambios
}

/// Log a archivo: tamaño máximo de cada `Ellkan.log` y cuántos anteriores se
/// guardan (5 MB × (1 + 3) ≈ 20 MB como tope en disco).
const LOG_MAX_BYTES: u128 = 5_000_000;
const LOG_ARCHIVOS_VIEJOS: usize = 3;
/// Target de los mensajes que manda la interfaz (`registrar_desde_web`).
const TARGET_WEB: &str = "ellkan_web";
/// Largo máximo de un mensaje de la interfaz: un error con un objeto enorme
/// no puede llenar el archivo de una vez.
const LOG_MAX_MENSAJE_WEB: usize = 2_000;

/// Errores y avisos de la interfaz (`console.error`/`console.warn`, errores
/// sin capturar) al mismo `Ellkan.log` que el backend. Antes se perdían: la
/// consola de WebView2 no está abierta en release. La interfaz nunca manda
/// secretos acá (mismo criterio que sus `console.error`: ids y mensajes de
/// error); igual se recorta el largo y se sacan caracteres de control para
/// que nadie pueda falsear líneas del log.
#[tauri::command]
fn registrar_desde_web(nivel: String, mensaje: String) {
  let limpio: String = mensaje
    .chars()
    .map(|c| if c.is_control() { ' ' } else { c })
    .take(LOG_MAX_MENSAJE_WEB)
    .collect();
  match nivel.as_str() {
    "error" => log::error!(target: TARGET_WEB, "{limpio}"),
    "warn" => log::warn!(target: TARGET_WEB, "{limpio}"),
    _ => log::info!(target: TARGET_WEB, "{limpio}"),
  }
}

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

/// Revocación remota (docs/revocacion-remota.md), lo que vive fuera de la
/// carpeta de datos: la credencial del llavero de Windows (desbloqueo rápido,
/// F-50) y `desktop.json`.
fn borrar_restos_de_revocacion() {
  sistema::borrar_credenciales_llavero();
  let config = std::env::var_os("ELLKAN_CONFIG_DIR")
    .map(PathBuf::from)
    .or_else(|| std::env::var_os("USERPROFILE").map(|u| PathBuf::from(u).join(".ellkan")));
  if let Some(config) = config {
    let _ = std::fs::remove_file(config.join("desktop.json"));
  }
}

/// Arranque con un borrado remoto que quedó a medias (un archivo bloqueado):
/// se completa antes de abrir la base. Si vuelve a fallar, la marca queda y
/// el backend local no sirve nada hasta el próximo intento (ver `router`).
fn ejecutar_borrado_remoto(dir: &std::path::Path) {
  match ellkan_backend::desktop::borrado_remoto::ejecutar(dir) {
    Ok(()) => log::warn!("borrado remoto completado al arrancar"),
    Err(e) => log::error!("{e:#}"),
  }
  borrar_restos_de_revocacion();
}

/// Lo llama el frontend apenas el backend local borró la bóveda por
/// revocación remota.
#[tauri::command]
fn limpiar_restos_revocacion() {
  borrar_restos_de_revocacion();
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
      "El puerto {puerto} está reservado por el sistema operativo — elegí uno de 1024 en adelante (se sugiere el rango 36000-47999)."
    ));
  }

  // Bind de prueba real: confirma disponibilidad ahora mismo. El listener
  // se suelta al salir de scope (nunca se guarda ni se sirve nada en él) —
  // no elimina la posibilidad de una carrera con otro proceso entre este
  // chequeo y el próximo arranque real, pero es la misma garantía (ni más
  // ni menos) que ya acepta `bindear_puerto` para el puerto autoelegido.
  tokio::net::TcpListener::bind(("127.0.0.1", puerto)).await.map_err(|e| {
    // 10013: Windows lo tiene en un rango excluido (Hyper-V/WSL/Docker), no es que esté en uso.
    if e.kind() == std::io::ErrorKind::PermissionDenied || e.raw_os_error() == Some(10013) {
      format!(
        "Windows tiene reservado el puerto {puerto} (Hyper-V, WSL o Docker). Elegí otro, idealmente entre 36000 y 47999; los rangos reservados se ven con «netsh int ipv4 show excludedportrange protocol=tcp»."
      )
    } else {
      format!("el puerto {puerto} está ocupado por otro programa ahora mismo: {e}")
    }
  })?;

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
async fn preparar_backend_local(
) -> anyhow::Result<(tokio::net::TcpListener, u16, axum::Router, Option<ellkan_backend::desktop::FalloPuertoFijo>)> {
  let dir = datadir();
  std::fs::create_dir_all(&dir)?;

  // Revocación remota: si el servidor vinculado revocó la cuenta, la bóveda se
  // borra ACÁ, antes de abrir la base (con la app corriendo estaba en uso).
  if ellkan_backend::desktop::borrado_remoto::pendiente(&dir) {
    ejecutar_borrado_remoto(&dir);
  }

  let pool = ellkan_backend::desktop::bootstrap_sqlite(&dir).await?;
  let server_public_key = ellkan_backend::desktop::cargar_o_generar_server_key(&pool).await?;
  let secrets_key = ellkan_backend::desktop::cargar_o_generar_secrets_key(&pool).await?;

  let estado = ellkan_backend::desktop::state::AppStateDesktop::nuevo(dir.clone(), pool, server_public_key, secrets_key);
  let router = ellkan_backend::desktop::router::construir_router_desktop(estado);

  let (listener, puerto, fallo_fijo) = ellkan_backend::desktop::bindear_puerto(&dir).await?;

  // F-56: canal de la extensión por native messaging + tubería, sin TCP. Si
  // no se puede crear, la extensión sigue pudiendo usar el puerto (fallback).
  #[cfg(windows)]
  let tuberia_extension = match canal_extension::iniciar(router.clone()) {
    Ok(nombre) => {
      if let Err(e) = canal_extension::registrar_host(&dir) {
        log::warn!("no se registró el host de native messaging: {e}");
      }
      Some(nombre)
    }
    Err(e) => {
      log::warn!("canal de la extensión no disponible: {e}");
      None
    }
  };
  #[cfg(not(windows))]
  let tuberia_extension: Option<String> = None;
  ellkan_backend::desktop::escribir_desktop_json(puerto, VERSION_APP, tuberia_extension.as_deref())?;

  // Si el puerto fijo no se pudo usar se devuelve por qué (ocupado o
  // reservado por Windows) para avisarle al usuario (F-52), no fallar en silencio.
  Ok((listener, puerto, router, fallo_fijo))
}

/// Busca `nombre_exe` en `%PATH%` (y en el alias de apps empaquetadas de
/// Windows, `%LOCALAPPDATA%\Microsoft\WindowsApps\`, donde vive `wt.exe`
/// cuando Windows Terminal viene de la Store en vez de un PATH clásico) —
/// sin `std::process::Command::new(nombre).spawn()` de prueba, que
/// abriría una ventana real sólo para chequear disponibilidad.
///
/// Secuestro de PATH: el que gana es el primer `ssh.exe` que aparezca, y a
/// `ssh` le llega la contraseña (askpass). Si una carpeta escribible por el
/// usuario quedó antes que `System32` en el PATH, alcanza con dejar ahí un
/// `ssh.exe` falso. Por eso los clientes que Windows trae de fábrica se buscan
/// primero en el directorio del sistema, y del PATH se ignoran las entradas
/// relativas (`.`, vacías), que se resolverían contra el directorio actual.
#[cfg(target_os = "windows")]
fn buscar_en_path(nombre_exe: &str) -> Option<PathBuf> {
  if let Some(ruta) = buscar_en_sistema(nombre_exe) {
    return Some(ruta);
  }
  if let Ok(path_var) = std::env::var("PATH") {
    for dir in std::env::split_paths(&path_var).filter(|d| d.is_absolute()) {
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

/// Clientes que vienen con Windows y su carpeta dentro de `System32`.
#[cfg(target_os = "windows")]
const CLIENTES_DEL_SISTEMA: &[(&str, &str)] = &[
  ("ssh.exe", "OpenSSH"),
  ("ftp.exe", ""),
  ("telnet.exe", ""),
  ("mstsc.exe", ""),
  ("powershell.exe", r"WindowsPowerShell\v1.0"),
];

/// Ruta absoluta de un cliente de `CLIENTES_DEL_SISTEMA` si está instalado.
/// El directorio sale de `GetSystemDirectoryW` y no de `%SystemRoot%`, que es
/// una variable de entorno más y se hereda de quien lanzó la app.
#[cfg(target_os = "windows")]
fn buscar_en_sistema(nombre_exe: &str) -> Option<PathBuf> {
  use windows::Win32::System::SystemInformation::GetSystemDirectoryW;

  let (_, subcarpeta) = CLIENTES_DEL_SISTEMA.iter().find(|(nombre, _)| nombre.eq_ignore_ascii_case(nombre_exe))?;
  let mut buffer = [0u16; 512];
  // SAFETY: la API escribe como máximo `buffer.len()` unidades y devuelve
  // cuántas usó (o el tamaño necesario, si no alcanzó).
  let largo = unsafe { GetSystemDirectoryW(Some(&mut buffer)) } as usize;
  if largo == 0 || largo >= buffer.len() {
    return None;
  }
  let candidato = PathBuf::from(String::from_utf16_lossy(&buffer[..largo])).join(subcarpeta).join(nombre_exe);
  candidato.is_file().then_some(candidato)
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

/// Separador de argumentos en `ELLKAN_CONECTAR_ARGV` (carácter de control
/// "unit separator"): no puede aparecer en ningún argumento válido.
#[cfg(target_os = "windows")]
const SEPARADOR_ARGV: char = '\u{1F}';

/// Comando FIJO que corre la consola de PowerShell cuando no hay Windows
/// Terminal. Los datos (programa, argumentos, título) llegan por variables de
/// entorno y se usan como valores, nunca se interpolan en el texto del comando:
/// un `host` raro no puede convertirse en código. Las variables se borran antes
/// de ejecutar, y el secreto nunca pasa por acá (lo trae el lanzador).
#[cfg(target_os = "windows")]
const COMANDO_POWERSHELL: &str = "$a = @($env:ELLKAN_CONECTAR_ARGV -split [char]0x1F); \
  $Host.UI.RawUI.WindowTitle = $env:ELLKAN_CONECTAR_TITULO; \
  Remove-Item Env:ELLKAN_CONECTAR_ARGV, Env:ELLKAN_CONECTAR_TITULO; \
  $r = @($a | Select-Object -Skip 1); & $a[0] $r";

/// Título de la pestaña o ventana: sin caracteres de control ni `;` (que
/// `wt` interpreta como separador de comandos), y corto.
#[cfg(target_os = "windows")]
fn titulo_seguro(titulo: Option<&str>, tipo: &str, host: &str) -> String {
  let limpio: String = titulo
    .unwrap_or_default()
    .chars()
    .filter(|c| !c.is_control() && *c != ';')
    .take(60)
    .collect::<String>()
    .trim()
    .to_string();
  if limpio.is_empty() { format!("{tipo} · {host}") } else { limpio }
}

/// Arma el `Command` que abre `argv` en una terminal interactiva (sin esto,
/// `ssh`/`ftp`/`telnet` heredarían la consola de este proceso, que no es una
/// terminal real):
/// - Con Windows Terminal: `wt -w ellkan new-tab --title … -- argv…`. Todas
///   las conexiones van como pestañas de una misma ventana «ellkan», o una
///   ventana nueva cada vez (`-w new`) si el usuario lo prefiere.
/// - Sin Windows Terminal: una consola de PowerShell (`System32`) que ejecuta
///   `argv` con `COMANDO_POWERSHELL` y queda abierta al terminar.
///
/// Nunca se arma un texto de comando con los datos (`cmd /c "…"`,
/// `powershell -Command "… host …"`): `host`/`usuario` pueden venir de un import
/// CSV/KDBX externo (F-27), así que cada valor viaja como argumento separado o
/// como valor de una variable de entorno.
#[cfg(target_os = "windows")]
fn comando_en_terminal(argv: &[String], titulo: &str, en_pestanas: bool) -> std::process::Command {
  use std::os::windows::process::CommandExt;
  const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;

  if let Some(wt) = buscar_en_path("wt.exe") {
    // `--` le dice a `wt` que todo lo que sigue es el programa+argumentos a
    // ejecutar tal cual, no opciones propias de `wt`.
    let mut c = std::process::Command::new(wt);
    c.args(["-w", if en_pestanas { "ellkan" } else { "new" }, "new-tab", "--title", titulo, "--"]);
    c.args(argv);
    return c;
  }

  // PowerShell 5.1 descarta los argumentos vacíos al llamar un programa: si
  // hubiera alguno (o el separador), se lanza el programa directo.
  let argv_apto = argv.iter().all(|a| !a.is_empty() && !a.contains(SEPARADOR_ARGV));
  if let Some(powershell) = buscar_en_sistema("powershell.exe").filter(|_| argv_apto) {
    let mut c = std::process::Command::new(powershell);
    c.args(["-NoLogo", "-NoProfile", "-NoExit", "-Command", COMANDO_POWERSHELL]);
    c.env("ELLKAN_CONECTAR_ARGV", argv.join(&SEPARADOR_ARGV.to_string()));
    c.env("ELLKAN_CONECTAR_TITULO", titulo);
    c.creation_flags(CREATE_NEW_CONSOLE);
    return c;
  }

  let mut c = std::process::Command::new(&argv[0]);
  c.args(&argv[1..]);
  c.creation_flags(CREATE_NEW_CONSOLE);
  c
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
///
/// En una terminal, `ssh`/`psql`/`mysql` no se lanzan directo: los lanza
/// `ellkan_askpass.exe --lanzar`, que recibe el secreto por una tubería de un
/// solo uso (`tuberia.rs`). Con pestañas de Windows Terminal el proceso de la
/// pestaña no hereda el entorno de esta app, así que el secreto no puede viajar
/// como variable de entorno desde acá.
///
/// `titulo` (nombre del recurso) va en la pestaña; `en_pestanas` (por defecto
/// sí) elige entre una ventana «ellkan» con pestañas o una ventana por conexión.
#[cfg(target_os = "windows")]
#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn conectar_recurso(
  tipo: String,
  usuario: Option<String>,
  host: String,
  puerto: u16,
  secreto: String,
  titulo: Option<String>,
  en_pestanas: Option<bool>,
) -> Result<(), String> {
  use ellkan_backend::desktop::conectar::{planificar, Inyeccion, Ventana};

  let secreto = Zeroizing::new(secreto);
  let plan = planificar(&tipo, usuario.as_deref(), &host, puerto)?;
  let programa = plan.programas.iter().find_map(|nombre| buscar_en_path(nombre)).ok_or_else(|| plan.falta.to_string())?;

  let mut comando = match plan.ventana {
    Ventana::Terminal => {
      let mut argv: Vec<String> = Vec::new();
      let modo = match plan.inyeccion {
        Inyeccion::Askpass => Some("askpass".to_string()),
        Inyeccion::Entorno(variable) => Some(format!("env:{variable}")),
        _ => None,
      };
      if let Some(modo) = modo {
        let lanzador = ruta_askpass_helper()
          .map_err(|e| format!("no se pudo preparar la conexión asistida ({e:#}) — copiá el comando y pegá la contraseña a mano"))?;
        let tuberia = tuberia::servir_secreto_una_vez(Zeroizing::new(secreto.to_string()), &lanzador)?;
        argv.extend([lanzador.to_string_lossy().into_owned(), "--lanzar".into(), tuberia, modo, "--".into()]);
      }
      argv.push(programa.to_string_lossy().into_owned());
      argv.extend(plan.args.iter().cloned());
      let titulo = titulo_seguro(titulo.as_deref(), &tipo, &host);
      comando_en_terminal(&argv, &titulo, en_pestanas.unwrap_or(true))
    }
    Ventana::Propia => {
      let mut c = std::process::Command::new(&programa);
      c.args(&plan.args);
      c
    }
  };

  let mut credencial_rdp = false;
  match plan.inyeccion {
    // En terminal el secreto ya lo entrega la tubería (arriba).
    Inyeccion::Askpass | Inyeccion::Entorno(_) if plan.ventana == Ventana::Terminal => {}
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
#[allow(clippy::too_many_arguments)]
fn conectar_recurso(
  tipo: String,
  usuario: Option<String>,
  host: String,
  puerto: u16,
  secreto: String,
  titulo: Option<String>,
  en_pestanas: Option<bool>,
) -> Result<(), String> {
  let _ = (tipo, usuario, host, puerto, secreto, titulo, en_pestanas);
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
  esconder_ventana(&ventana);
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
    version: VERSION_APP.to_string(),
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

/// Linux: el caché de WebKitGTK viene pensado para un navegador (páginas
/// anteriores en memoria, recursos de muchos sitios). Ellkan es una sola
/// página local: `DocumentViewer` deja esos cachés al mínimo.
#[cfg(target_os = "linux")]
fn ajustar_webview_linux(app: &tauri::AppHandle) {
  let Some(ventana) = app.get_webview_window("main") else { return };
  let resultado = ventana.with_webview(|webview| {
    use webkit2gtk::{CacheModel, WebContextExt, WebViewExt};
    if let Some(contexto) = webview.inner().context() {
      contexto.set_cache_model(CacheModel::DocumentViewer);
    }
  });
  if let Err(e) = resultado {
    log::warn!("no se pudo ajustar el caché de WebKit: {e}");
  }
}

#[cfg(not(target_os = "linux"))]
fn ajustar_webview_linux(_app: &tauri::AppHandle) {}

/// Esconde la ventana (queda la bandeja) y le pide a WebView2 que suelte memoria.
fn esconder_ventana(ventana: &tauri::WebviewWindow) {
  let _ = ventana.hide();
  memoria_baja(ventana, true);
}

/// Trae la ventana al frente, también si estaba minimizada, con la memoria normal.
fn mostrar_ventana(ventana: &tauri::WebviewWindow) {
  memoria_baja(ventana, false);
  let _ = ventana.show();
  let _ = ventana.unminimize();
  let _ = ventana.set_focus();
}

/// Mientras nadie ve la ventana (en la bandeja o minimizada), WebView2 puede
/// soltar cachés y memoria de la página. No la suspende: el bloqueo por
/// inactividad y los eventos desde Rust siguen funcionando.
#[cfg(windows)]
fn memoria_baja(ventana: &tauri::WebviewWindow, baja: bool) {
  use std::sync::atomic::{AtomicBool, Ordering};
  // Sólo la ventana principal pasa por acá; evita repetir la llamada en cada `Resized`.
  static ACTUAL: AtomicBool = AtomicBool::new(false);
  if ACTUAL.swap(baja, Ordering::Relaxed) == baja {
    return;
  }
  let resultado = ventana.with_webview(move |webview| {
    use webview2_com::Microsoft::Web::WebView2::Win32::{
      COREWEBVIEW2_MEMORY_USAGE_TARGET_LEVEL_LOW, COREWEBVIEW2_MEMORY_USAGE_TARGET_LEVEL_NORMAL, ICoreWebView2_19,
    };
    use windows::core::Interface;
    let nivel = if baja { COREWEBVIEW2_MEMORY_USAGE_TARGET_LEVEL_LOW } else { COREWEBVIEW2_MEMORY_USAGE_TARGET_LEVEL_NORMAL };
    // SAFETY: COM sobre el controlador vivo de esta ventana, en el hilo de la
    // interfaz (donde `with_webview` corre el callback).
    let r = unsafe {
      webview
        .controller()
        .CoreWebView2()
        .and_then(|w| w.cast::<ICoreWebView2_19>())
        .and_then(|w| w.SetMemoryUsageTargetLevel(nivel))
    };
    if let Err(e) = r {
      log::warn!("no se pudo ajustar la memoria de WebView2: {e}");
    }
  });
  if let Err(e) = resultado {
    log::warn!("no se pudo ajustar la memoria de WebView2: {e}");
  }
}

#[cfg(not(windows))]
fn memoria_baja(_ventana: &tauri::WebviewWindow, _baja: bool) {}

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

/// Copia un secreto al portapapeles sin que Windows lo guarde en el historial
/// (`Win+V`) ni lo suba a la nube. Fuera de Windows responde error y el
/// frontend usa el portapapeles del webview.
#[cfg(windows)]
#[tauri::command]
fn copiar_secreto(ventana: tauri::WebviewWindow, texto: String) -> Result<(), String> {
  let texto = Zeroizing::new(texto);
  let hwnd = ventana.hwnd().map_err(|e| e.to_string())?;
  sistema::copiar_sin_historial(hwnd, &texto)
}

#[cfg(not(windows))]
#[tauri::command]
fn copiar_secreto(texto: String) -> Result<(), String> {
  drop(Zeroizing::new(texto));
  Err("no soportado en esta plataforma".to_string())
}

/// Vacía el portapapeles: la auto-limpieza de lo que dejó `copiar_secreto`.
#[cfg(windows)]
#[tauri::command]
fn vaciar_portapapeles(ventana: tauri::WebviewWindow) -> Result<(), String> {
  let hwnd = ventana.hwnd().map_err(|e| e.to_string())?;
  sistema::vaciar_portapapeles(hwnd)
}

#[cfg(not(windows))]
#[tauri::command]
fn vaciar_portapapeles() -> Result<(), String> {
  Err("no soportado en esta plataforma".to_string())
}

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

  // Linux: WebKitGTK reserva buffers grandes para la composición acelerada
  // (animaciones por GPU), que una app de formularios no necesita: sin ella el
  // proceso web usa bastante menos memoria. `ELLKAN_WEBKIT_COMPOSICION=1` la
  // deja activa por si en algún equipo se ve peor.
  #[cfg(target_os = "linux")]
  if std::env::var_os("WEBKIT_DISABLE_COMPOSITING_MODE").is_none() && std::env::var_os("ELLKAN_WEBKIT_COMPOSICION").is_none() {
    // SAFETY: todavía no se lanzó ningún hilo (ni Tauri ni el backend), así
    // que nadie más lee el entorno mientras se modifica.
    unsafe { std::env::set_var("WEBKIT_DISABLE_COMPOSITING_MODE", "1") };
  }

  // Windows: WebView2 arranca como un navegador completo (proceso de GPU,
  // telemetría, actualizador de componentes, informes de fallos). Ellkan es
  // una sola página local de formularios: sin GPU (dibuja por CPU dentro del
  // proceso principal, un proceso menos) y sin tráfico de fondo hacia
  // Microsoft. La variable de entorno vale para todas las ventanas (la
  // principal y el aviso): WebView2 rechaza crear una segunda ventana con
  // argumentos distintos a la primera. Se repiten los `--disable-features`
  // que Tauri pone por defecto, porque esta variable los reemplaza.
  // `ELLKAN_WEBVIEW_GPU=1` deja la GPU activa por si en algún equipo se ve peor.
  #[cfg(windows)]
  if std::env::var_os("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS").is_none() {
    let mut args = String::from(
      "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection,Translate,OptimizationHints,MediaRouter,AutofillServerCommunication,SpareRendererForSitePerProcess,BackForwardCache \
       --renderer-process-limit=1 --disable-background-networking --disable-component-update --disable-domain-reliability \
       --disable-breakpad --disable-sync --no-pings",
    );
    if std::env::var_os("ELLKAN_WEBVIEW_GPU").is_none() {
      args.push_str(" --disable-gpu --in-process-gpu");
    }
    // SAFETY: igual que arriba, todavía no hay otros hilos.
    unsafe { std::env::set_var("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", args) };
  }

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
        mostrar_ventana(&ventana);
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
      registrar_desde_web,
      tomar_cambios_extension,
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
      simular_bloqueo_de_pantalla,
      copiar_secreto,
      vaciar_portapapeles,
      limpiar_restos_revocacion
    ])
    // F-45: qué hace la "X" depende de la preferencia del usuario (`AlCerrar`).
    // Antes SIEMPRE ocultaba a la bandeja sin avisar: el usuario "cerraba" la
    // app, seguía corriendo, y al abrir el `.exe` de nuevo (la app es de
    // instancia única) volvía a ver la ventana vieja. Ahora, por defecto, se
    // le pregunta.
    .on_window_event(|window, event| {
      // Minimizada desde la barra de título o la barra de tareas: misma
      // memoria baja que en la bandeja; al restaurarla, vuelve a la normal.
      if let tauri::WindowEvent::Resized(_) = event
        && window.label() == "main"
        && window.is_visible().unwrap_or(false)
        && let Some(ventana) = window.app_handle().get_webview_window("main")
      {
        memoria_baja(&ventana, window.is_minimized().unwrap_or(false));
      }
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
            if let Some(ventana) = window.app_handle().get_webview_window("main") {
              esconder_ventana(&ventana);
            }
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
      // rotación: hasta `LOG_MAX_BYTES` por archivo y los `LOG_ARCHIVOS_VIEJOS`
      // anteriores; lo más viejo se borra solo, nunca pasa de ~20 MB.
      //
      // 2026-10-18: antes en release sólo guardaba avisos y errores, y el
      // «error interno» del sync no dejó ni una línea para diagnosticar. Ahora
      // el código de Ellkan (app + backend local + errores de la interfaz,
      // `registrar_desde_web`) va en `info`; las dependencias (webview, sqlx,
      // hyper…) siguen en `warn` para no llenarlo de ruido. Nunca secretos:
      // el backend sólo registra método, ruta, status y latencia.
      let mut registro = tauri_plugin_log::Builder::default()
        .max_file_size(LOG_MAX_BYTES)
        .rotation_strategy(tauri_plugin_log::RotationStrategy::KeepSome(LOG_ARCHIVOS_VIEJOS))
        .level(log::LevelFilter::Warn)
        .level_for("ellkan_desktop_lib", log::LevelFilter::Info)
        .level_for("ellkan_desktop", log::LevelFilter::Info)
        .level_for("ellkan_backend", log::LevelFilter::Info)
        .level_for(TARGET_WEB, log::LevelFilter::Info);
      if !cfg!(debug_assertions) {
        // Release: sin consola, sólo el archivo.
        registro = registro
          .clear_targets()
          .target(tauri_plugin_log::Target::new(tauri_plugin_log::TargetKind::LogDir { file_name: None }));
      }
      app.handle().plugin(registro.build())?;
      log::info!(
        "Ellkan {VERSION_APP} iniciando — {} {}, {}, datos en {}",
        std::env::consts::OS,
        std::env::consts::ARCH,
        if portable::activo() { "modo portable" } else { "instalada" },
        datadir().display()
      );

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
                esconder_ventana(&ventana);
              } else {
                mostrar_ventana(&ventana);
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
                  mostrar_ventana(&ventana);
                }
              }
              "bloquear" => {
                if let Some(ventana) = app.get_webview_window("main") {
                  let _ = ventana.emit("bloquear-boveda", ());
                  mostrar_ventana(&ventana);
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
                  esconder_ventana(&ventana);
                } else {
                  mostrar_ventana(&ventana);
                }
              }
            }
          })
          .build(app)?;
      }

      // Cuando la extensión cambia un recurso (por native messaging o por el
      // puerto TCP), el backend local avisa acá y se le pasa a la interfaz
      // para que lo suba al servidor vinculado (`cambios_extension`).
      let _ = APP.set(app.handle().clone());
      ellkan_backend::desktop::cambios_extension::al_cambiar(|id, operacion| {
        use tauri::Emitter;
        // Primero al archivo: si la bóveda está bloqueada nadie escucha el
        // evento y el cambio se perdía (bug real 2026-10-18).
        anotar_cambio_de_extension(id, operacion);
        if let Some(app) = APP.get() {
          let _ = app.emit("recurso-cambiado-por-extension", serde_json::json!({ "id": id, "operacion": operacion }));
        }
      });

      match tauri::async_runtime::block_on(preparar_backend_local()) {
        Ok((listener, puerto, router, fallo_fijo)) => {
          app.manage(PuertoBackend(puerto));
          if let Some(fallo) = fallo_fijo {
            let esperado = fallo.puerto;
            let tipo = match (fallo.reservado, fallo.reemplazado) {
              (true, true) => "puerto_reservado_cambiado",
              (true, false) => "puerto_reservado",
              (false, _) => "puerto",
            };
            log::warn!("el puerto fijo {esperado} no estaba disponible ({tipo}): se usa el {puerto}");
            mostrar_aviso(app.handle(), serde_json::json!({ "tipo": tipo, "esperado": esperado, "actual": puerto }));
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
        esconder_ventana(&ventana);
      }

      vigilar_bloqueo_de_pantalla(app.handle());
      ajustar_webview_linux(app.handle());

      Ok(())
    })
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}

// El desbloqueo rápido con el llavero de Windows (F-50) usa estos tres comandos. Se probó
// que nada se guardaba: `keyring` estaba compilado sin el almacén nativo, así que usaba
// uno de prueba en memoria. Esta prueba lo ejerce contra el Administrador de credenciales
// real, con un id propio que limpia al terminar.
#[cfg(test)]
mod pruebas_version {
  #[test]
  fn la_version_de_la_app_es_la_de_tauri_conf() {
    let conf: serde_json::Value = serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
    assert_eq!(super::VERSION_APP, conf["version"].as_str().unwrap());
    let partes: Vec<&str> = super::VERSION_APP.split('.').collect();
    assert_eq!(partes.len(), 3, "el MSI exige major.minor.patch");
    assert!(partes.iter().all(|p| p.parse::<u32>().is_ok()));
  }
}

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
