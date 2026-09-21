// Autor: Athan Espinoza

//! Modo escritorio (v2, spec/13-aplicacion-escritorio-diseno.md). Bootstrap
//! del motor de datos (SQLite embebido, §4) + descubrimiento del backend
//! local (puerto real + `desktop.json`, §3, desde 2026-09-16). `sync`/
//! `launcher` (fase 3.2/3.3) quedan para cuando se ataquen esos slices.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;

pub mod conectar;
pub mod descargas;
pub mod enlaces;
pub mod extension;
pub mod origen;
pub mod repositories;
pub mod respaldos;
pub mod router;
pub mod sqlite_util;
pub mod state;

/// Abre (o crea) `<datadir>/ellkan.db`, fija WAL mode (lectores concurrentes
/// mientras hay un escritor — cubre GUI + extensión + CLI + sync pegándole
/// al mismo backend local, spec/13 §4) y corre las migraciones SQLite del
/// subconjunto de módulos de escritorio ya migrados.
pub async fn bootstrap_sqlite(datadir: &Path) -> anyhow::Result<SqlitePool> {
    let db_path = datadir.join("ellkan.db");
    let opciones = SqliteConnectOptions::new().filename(&db_path).create_if_missing(true);

    let pool = SqlitePoolOptions::new().connect_with(opciones).await?;
    sqlx::query("PRAGMA journal_mode = WAL").execute(&pool).await?;

    // Ruta relativa a `CARGO_MANIFEST_DIR` (`backend/`, no a este archivo) —
    // así resuelve la macro `sqlx::migrate!`, sin importar que este módulo
    // viva físicamente en `app-escritorio/` vía `#[path]` en `lib.rs`.
    //
    // Hallazgo real 2026-09-16: agregar un archivo NUEVO a esta carpeta no
    // siempre dispara un recompile incremental (el macro trackea el
    // contenido de los archivos que ya conocía, no necesariamente "apareció
    // uno nuevo") — si una migración nueva parece no aplicarse tras
    // `cargo run` sin tocar ningún `.rs`, forzar el recompile tocando esta
    // misma línea es el mecanismo conocido para des-atascarlo.
    let migrador = sqlx::migrate!("../app-escritorio/backend-desktop/migrations_sqlite");

    // F-53: `ellkan.db` es la única copia de los datos del usuario. Si esta
    // versión de la app trae migraciones nuevas, se guarda una copia ANTES de
    // aplicarlas; si la copia falla no se migra (mejor no arrancar que arriesgar
    // la bóveda sin red de seguridad).
    if let Some(version) = respaldos::version_previa_si_hay_pendientes(&pool, &migrador).await? {
        let copia = respaldos::respaldar(&pool, datadir, respaldos::PREFIJO_AUTOMATICO, &format!("v{version:04}-"))
            .await
            .map_err(|e| e.context("no se pudo respaldar la bóveda antes de actualizar su esquema"))?;
        tracing::info!(copia = %copia.display(), "copia de seguridad antes de migrar");
    }

    migrador.run(&pool).await?;

    Ok(pool)
}

/// Mismo criterio que `cargar_o_generar_server_key` (Postgres, `lib.rs`):
/// identidad Ed25519 propia del backend local (`GET /auth/server-key`), se
/// genera una sola vez y se persiste para que no cambie en cada arranque.
pub async fn cargar_o_generar_server_key(pool: &SqlitePool) -> anyhow::Result<[u8; 32]> {
    use sqlx::Row;

    if let Some(fila) = sqlx::query("select public_key_ed25519 from server_keys where id = 1")
        .fetch_optional(pool)
        .await?
    {
        let bytes: Vec<u8> = fila.get("public_key_ed25519");
        return Ok(bytes.try_into().expect("32 bytes"));
    }

    let par = ellkan_crypto::claves::KeypairFirma::generar();
    let publica = par.verificadora().to_bytes();
    let privada = par.firmante().to_bytes();

    sqlx::query("insert into server_keys (id, public_key_ed25519, private_key_ed25519) values (1, ?1, ?2)")
        .bind(&publica[..])
        .bind(&privada[..])
        .execute(pool)
        .await?;

    Ok(publica)
}

/// F-14: en modo servidor `ELLKAN_SECRETS_KEY` la fija el operador
/// (`config.rs`); en modo escritorio no hay operador — se genera una sola
/// vez (CSPRNG, nunca `thread_rng`) y se persiste, mismo criterio que
/// `cargar_o_generar_server_key`.
pub async fn cargar_o_generar_secrets_key(pool: &SqlitePool) -> anyhow::Result<ellkan_crypto::secretos::ClaveSecreta32> {
    use secrecy::SecretBox;
    use sqlx::Row;

    if let Some(fila) = sqlx::query("select secrets_key from desktop_secrets where id = 1").fetch_optional(pool).await? {
        let bytes: Vec<u8> = fila.get("secrets_key");
        let arr: [u8; 32] = bytes.try_into().expect("32 bytes");
        return Ok(SecretBox::new(Box::new(arr)));
    }

    let bytes: [u8; 32] = ellkan_crypto::aleatoriedad::bytes_aleatorios();
    sqlx::query("insert into desktop_secrets (id, secrets_key) values (1, ?1)")
        .bind(&bytes[..])
        .execute(pool)
        .await?;

    Ok(SecretBox::new(Box::new(bytes)))
}

/// `~/.ellkan/` — el MISMO directorio que ya usa `ellkan-cli`
/// (`cli/src/config.rs::dir_config`) para `sesion.json`/`perfil.json`, y
/// donde este módulo escribe `desktop.json` (spec/13 §3) — necesario para
/// que la CLI/extensión encuentren el archivo de descubrimiento en el
/// lugar donde ya saben mirar. `ELLKAN_CONFIG_DIR` overridea, mismo
/// criterio que la CLI (tests/múltiples identidades en la misma máquina).
pub fn dir_home_ellkan() -> anyhow::Result<PathBuf> {
    let dir = if let Ok(ruta) = std::env::var("ELLKAN_CONFIG_DIR") {
        PathBuf::from(ruta)
    } else {
        let base = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("no se pudo resolver el home del usuario"))?;
        base.join(".ellkan")
    };
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// H-12 (mismo criterio que `cli/src/config.rs::escribir_archivo_privado`):
/// crea el archivo con permisos restringidos en la MISMA syscall que lo
/// crea — sin la ventana TOCTOU de un `write` seguido de un `chmod` aparte.
#[cfg(unix)]
fn escribir_archivo_privado(ruta: &Path, contenido: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut archivo = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(ruta)?;
    archivo.write_all(contenido)?;
    Ok(())
}

/// En Windows no existe el bit 0600 de POSIX — el ACL por defecto del
/// perfil del usuario ya restringe el acceso a otras cuentas locales
/// (mismo criterio y misma limitación aceptada que la CLI).
#[cfg(not(unix))]
fn escribir_archivo_privado(ruta: &Path, contenido: &[u8]) -> anyhow::Result<()> {
    std::fs::write(ruta, contenido)?;
    Ok(())
}

#[derive(Serialize)]
struct DesktopJson {
    port: u16,
    token: String,
    pid: u32,
    version: String,
}

/// Escribe `~/.ellkan/desktop.json` (spec/13 §3) — el archivo de
/// descubrimiento por el que la extensión y la CLI encuentran el backend
/// local en curso. Se reescribe en cada arranque (puerto/pid/token pueden
/// cambiar de una corrida a otra).
///
/// `token`: hoy es un valor aleatorio nuevo por arranque, generado acá y
/// **sin ningún consumidor todavía** — spec/13 §3 lo describe como "bearer
/// de sesión de la app", pensado para que la extensión/CLI emparejadas
/// (F-56, fase 3.2) puedan actuar sobre la sesión ya desbloqueada sin
/// loguearse de nuevo. Ese emparejamiento no existe todavía: se persiste el
/// campo con la forma que pide la spec para no romper a futuros
/// consumidores, pero no reemplaza ni debilita el `Authorization: Bearer
/// <session_id>` real que `AuthenticatedUserDesktop` ya exige en cada
/// request — ver `router.rs`.
pub fn escribir_desktop_json(port: u16, version: &str) -> anyhow::Result<()> {
    let token = crate::b64::encode(&ellkan_crypto::aleatoriedad::bytes_aleatorios::<32>());
    let datos = DesktopJson { port, token, pid: std::process::id(), version: version.to_string() };
    let ruta = dir_home_ellkan()?.join("desktop.json");
    escribir_archivo_privado(&ruta, &serde_json::to_vec_pretty(&datos)?)?;
    Ok(())
}

/// Modos de persistencia por bóveda (F-48):
/// - `Full`: réplica completa (metadata + secretos cifrados en SQLite local).
/// - `Memory`: metadata en SQLite; secretos sólo en memoria volátil.
/// - `NamesOnly`: sólo nombres y metadatos básicos en SQLite; secretos bajo demanda.
///
/// **Corrección 2026-09-17**: por ahora sólo un campo de configuración que
/// se guarda/carga — ningún código todavía branchea sobre su valor (no hay
/// purga real en `Memory` ni consulta on-demand en `NamesOnly`). Ver
/// `spec/05-plan-de-implementacion.md` línea 244.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ModoPersistencia {
    #[default]
    Full,
    Memory,
    NamesOnly,
}

/// Qué hace la app al cerrar la ventana con la "X" (o Alt+F4). Cerrar a la
/// bandeja (F-45) sin avisar hizo que dos veces el usuario "cerrara" la app y
/// siguiera corriendo — con el `.exe` bloqueado y sin entender por qué — así
/// que por defecto ahora se le pregunta.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AlCerrar {
    /// Muestra un diálogo con las dos opciones (y "recordar mi elección").
    #[default]
    Preguntar,
    /// La ventana se oculta y la app sigue corriendo en la bandeja del sistema.
    Bandeja,
    /// La app se cierra del todo.
    Salir,
}

/// Configuración de sincronización con servidor remoto (F-47).
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct ConfigSyncRemoto {
    #[serde(default)]
    pub server_url: Option<String>,
    #[serde(default)]
    pub sync_token: Option<String>,
    #[serde(default)]
    pub last_sync_at: Option<String>,
}

/// Configuración persistida de la app de escritorio en `<datadir>/config.json`.
#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct ConfigApp {
    #[serde(default)]
    pub puerto_fijo: Option<u16>,
    #[serde(default)]
    pub modo_persistencia: ModoPersistencia,
    #[serde(default)]
    pub sync_remoto: ConfigSyncRemoto,
    /// Navegadores para los que el usuario pidió instalar la extensión desde
    /// la app (ids de `extension::NAVEGADORES`). La app vuelve a extraer el
    /// bundle para cada uno en cada arranque si la versión no está al día —
    /// eso es lo que hace que la extensión "quede" y se actualice sola.
    #[serde(default)]
    pub extension_navegadores: Vec<String>,
    /// Qué pasa al cerrar la ventana — ver `AlCerrar`.
    #[serde(default)]
    pub al_cerrar: AlCerrar,
    /// Bloquear la bóveda cuando se bloquea la pantalla de Windows (F-52).
    /// `None` = no lo eligió: rige el valor por defecto (activado).
    #[serde(default)]
    pub bloquear_con_pantalla: Option<bool>,
}

impl ConfigApp {
    /// ¿Hay que bloquear la bóveda al bloquearse la sesión del sistema?
    /// Activado por defecto: es la opción segura.
    pub fn bloquear_con_pantalla_efectivo(&self) -> bool {
        self.bloquear_con_pantalla.unwrap_or(true)
    }
}

pub fn ruta_config(datadir: &Path) -> PathBuf {
    datadir.join("config.json")
}

pub fn cargar_config(datadir: &Path) -> anyhow::Result<ConfigApp> {
    let ruta = ruta_config(datadir);
    if !ruta.exists() {
        return Ok(ConfigApp::default());
    }
    Ok(serde_json::from_slice(&std::fs::read(&ruta)?)?)
}

pub fn guardar_config(datadir: &Path, config: &ConfigApp) -> anyhow::Result<()> {
    std::fs::write(ruta_config(datadir), serde_json::to_vec_pretty(config)?)?;
    Ok(())
}

/// Bindea el backend local a un puerto real (spec/13 §3). Si ya hay un
/// puerto fijo persistido (elegido por el usuario en Ajustes → Escritorio,
/// vía el comando Tauri `configurar_puerto_fijo`, o autoelegido en un
/// arranque anterior de este mismo mecanismo) intenta
/// bindearlo primero; si no existe todavía o ya está tomado por otro
/// proceso, prueba puertos al azar dentro del rango IANA privado/dinámico
/// (`49152-65535`, nunca asignado oficialmente a ningún servicio — mismo
/// rango que sugeriría el wizard) hasta lograr un bind real, y lo persiste
/// como el nuevo fijo si todavía no había ninguno.
///
/// **Nunca falla en silencio ni crashea el arranque**: si el puerto fijo
/// configurado no pudo bindearse, se loguea como advertencia y se sigue
/// con el fallback — la notificación nativa que spec/13 §3 pide para este
/// caso (F-52) todavía no existe, pendiente de esa fase.
pub async fn bindear_puerto(datadir: &Path) -> anyhow::Result<(tokio::net::TcpListener, u16)> {
    let mut config = cargar_config(datadir)?;

    if let Some(fijo) = config.puerto_fijo {
        match tokio::net::TcpListener::bind(("127.0.0.1", fijo)).await {
            Ok(listener) => return Ok((listener, fijo)),
            Err(e) => tracing::warn!(
                puerto = fijo,
                error = %e,
                "puerto fijo configurado no está disponible — se usa uno libre sólo para esta sesión"
            ),
        }
    }

    const RANGO_MIN: u16 = 49152;
    const RANGO_ANCHO: u16 = 65535 - RANGO_MIN;
    for _ in 0..50 {
        let bytes = ellkan_crypto::aleatoriedad::bytes_aleatorios::<2>();
        let candidato = RANGO_MIN + (u16::from_le_bytes(bytes) % RANGO_ANCHO);
        if let Ok(listener) = tokio::net::TcpListener::bind(("127.0.0.1", candidato)).await {
            if config.puerto_fijo.is_none() {
                config.puerto_fijo = Some(candidato);
                if let Err(e) = guardar_config(datadir, &config) {
                    tracing::warn!(puerto = candidato, error = %e, "no se pudo persistir el puerto elegido");
                }
            }
            return Ok((listener, candidato));
        }
    }

    // Últimos recursos: dejar que el SO elija (puerto 0) — no debería
    // llegar acá con 50 intentos sobre un rango de más de 16 mil puertos.
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let puerto = listener.local_addr()?.port();
    Ok((listener, puerto))
}
