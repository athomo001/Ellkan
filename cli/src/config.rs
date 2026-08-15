// Autor: Athan Espinoza

//! Config local de la CLI — F-35: precedencia flag > env > archivo > default,
//! archivo `0600` en POSIX. Vive en `~/.ellkan/` — perfil (claves ya
//! cifradas) y sesión (sólo el `session_id`, nunca la passphrase ni la clave
//! privada) en archivos separados.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Perfil {
    pub server_url: String,
    pub email: String,
    pub user_id: uuid::Uuid,
    pub public_key_x25519_b64: String,
    pub public_key_ed25519_b64: String,
    pub encrypted_private_key_blob_b64: String,
    pub private_key_nonce_b64: String,
    pub kdf_salt_b64: String,
    /// mTLS opcional (F-35) — `#[serde(default)]` para que perfiles ya
    /// persistidos sin estos campos sigan cargando sin error.
    #[serde(default)]
    pub client_cert_path: Option<String>,
    #[serde(default)]
    pub client_key_path: Option<String>,
    #[serde(default)]
    pub ca_bundle_path: Option<String>,
    /// Token de dispositivo persistente (F-02) — sólo su hash viaja al
    /// backend en cada `verify`; `#[serde(default)]` por la misma razón que
    /// los campos de mTLS.
    #[serde(default)]
    pub device_token_b64: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Sesion {
    pub session_id: uuid::Uuid,
}

fn dir_config() -> anyhow::Result<PathBuf> {
    // `ELLKAN_CONFIG_DIR` permite correr múltiples identidades en la misma
    // máquina (útil para tests/CI) — sin esto, `dirs::home_dir()` resuelve
    // siempre el mismo perfil de SO y no respeta overrides de `$HOME`.
    let dir = if let Ok(ruta) = std::env::var("ELLKAN_CONFIG_DIR") {
        PathBuf::from(ruta)
    } else {
        let base = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("no se pudo resolver el home del usuario"))?;
        base.join(".ellkan")
    };
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// H-12 (auditoría 2026-08-12): `fs::write` + `chmod 0600` por separado
/// dejaba una ventana TOCTOU — con el `umask` típico (022), el archivo
/// nacía `0644` (legible por cualquier usuario del sistema) entre la
/// creación y el chmod posterior. `sesion.json` guarda un `session_id`
/// (bearer credential), así que esa ventana era una fuga real, no teórica.
/// `OpenOptions::mode(0o600)` fija el modo en la misma syscall que crea el
/// archivo — nunca existe un instante con permisos más laxos.
#[cfg(unix)]
fn escribir_archivo_privado(ruta: &std::path::Path, contenido: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut archivo =
        std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(ruta)?;
    archivo.write_all(contenido)?;
    Ok(())
}

/// En Windows no existe el bit 0600 de POSIX — el ACL por defecto del
/// perfil del usuario ya restringe el acceso a otras cuentas locales;
/// endurecerlo más (ACL explícita) queda fuera de alcance de Fase 0.
#[cfg(not(unix))]
fn escribir_archivo_privado(ruta: &std::path::Path, contenido: &[u8]) -> anyhow::Result<()> {
    std::fs::write(ruta, contenido)?;
    Ok(())
}

fn ruta_perfil() -> anyhow::Result<PathBuf> {
    Ok(dir_config()?.join("perfil.json"))
}

fn ruta_sesion() -> anyhow::Result<PathBuf> {
    Ok(dir_config()?.join("sesion.json"))
}

pub fn guardar_perfil(perfil: &Perfil) -> anyhow::Result<()> {
    let ruta = ruta_perfil()?;
    escribir_archivo_privado(&ruta, &serde_json::to_vec_pretty(perfil)?)?;
    Ok(())
}

pub fn cargar_perfil() -> anyhow::Result<Perfil> {
    let ruta = ruta_perfil()?;
    let datos = std::fs::read(&ruta)
        .map_err(|_| anyhow::anyhow!("no hay perfil local — corré `ellkan-cli register` primero"))?;
    Ok(serde_json::from_slice(&datos)?)
}

pub fn guardar_sesion(sesion: &Sesion) -> anyhow::Result<()> {
    let ruta = ruta_sesion()?;
    escribir_archivo_privado(&ruta, &serde_json::to_vec_pretty(sesion)?)?;
    Ok(())
}

pub fn cargar_sesion() -> anyhow::Result<Sesion> {
    let ruta = ruta_sesion()?;
    let datos = std::fs::read(&ruta)
        .map_err(|_| anyhow::anyhow!("no hay sesión activa — corré `ellkan-cli login` primero"))?;
    Ok(serde_json::from_slice(&datos)?)
}

/// Precedencia F-35 (flag explícito, luego variable de entorno, luego
/// archivo de perfil, luego default): acá sólo se resuelve env/default
/// porque el flag, si viene, nunca llega a llamar a esta función (se usa
/// directo en el comando).
pub fn resolver_server_url(desde_perfil: Option<&str>) -> String {
    std::env::var("ELLKAN_SERVER_URL")
        .ok()
        .or_else(|| desde_perfil.map(str::to_string))
        .unwrap_or_else(|| "http://127.0.0.1:8080".to_string())
}

/// Misma precedencia F-35 que `resolver_server_url` (env > perfil, sin
/// default — mTLS es opt-in, `None` es el estado normal).
pub fn resolver_client_cert(desde_perfil: Option<&str>) -> Option<String> {
    std::env::var("ELLKAN_CLIENT_CERT").ok().or_else(|| desde_perfil.map(str::to_string))
}

pub fn resolver_client_key(desde_perfil: Option<&str>) -> Option<String> {
    std::env::var("ELLKAN_CLIENT_KEY").ok().or_else(|| desde_perfil.map(str::to_string))
}

pub fn resolver_ca_bundle(desde_perfil: Option<&str>) -> Option<String> {
    std::env::var("ELLKAN_CA_BUNDLE").ok().or_else(|| desde_perfil.map(str::to_string))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// H-12: `guardar_sesion` (y por extensión `guardar_perfil`, mismo
    /// helper) crea el archivo ya en `0600` — no sólo lo termina así, sin
    /// ventana intermedia con un modo más permisivo.
    #[test]
    fn guardar_sesion_crea_el_archivo_ya_en_0600() {
        let dir = std::env::temp_dir().join(format!("ellkan-cli-test-{}", uuid::Uuid::now_v7()));
        // SAFETY (test, single-threaded en este proceso a los efectos de esta
        // variable — ningún otro test del crate toca ELLKAN_CONFIG_DIR):
        // `set_var` es `unsafe` desde Rust 2024 por la posibilidad de carrera
        // entre threads mutando el entorno del proceso.
        unsafe { std::env::set_var("ELLKAN_CONFIG_DIR", &dir) };

        guardar_sesion(&Sesion { session_id: uuid::Uuid::now_v7() }).unwrap();

        let permisos = std::fs::metadata(dir.join("sesion.json")).unwrap().permissions();
        assert_eq!(permisos.mode() & 0o777, 0o600);

        unsafe { std::env::remove_var("ELLKAN_CONFIG_DIR") };
        std::fs::remove_dir_all(&dir).ok();
    }
}
