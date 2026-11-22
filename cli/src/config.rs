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
    // QA-46: la carpeta tampoco se lista para otros usuarios.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(dir)
}

/// H-12 + QA-46: `perfil.json` y `sesion.json` (un `session_id`, credencial
/// bearer) sólo los puede leer su dueño, aunque ya existieran con permisos
/// más laxos de una versión anterior. Escritura atómica: se escribe un
/// archivo temporal nuevo, que NACE privado (nunca hay un instante con otro
/// modo), y se renombra encima del definitivo. El rename reemplaza el
/// archivo viejo entero, con sus permisos viejos incluidos — un `chmod` al
/// archivo existente dejaría el contenido nuevo un instante con los
/// permisos viejos. Además, un corte a mitad nunca deja un JSON a medias.
fn escribir_archivo_privado(ruta: &std::path::Path, contenido: &[u8]) -> anyhow::Result<()> {
    let nombre = ruta
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow::anyhow!("ruta sin nombre de archivo"))?;
    let temporal = ruta.with_file_name(format!(".{nombre}.{}.tmp", uuid::Uuid::now_v7()));
    let resultado = crear_privado(&temporal, contenido).and_then(|()| reemplazar(&temporal, ruta));
    if resultado.is_err() {
        let _ = std::fs::remove_file(&temporal);
    }
    resultado
}

/// Crea `ruta` (no debe existir) ya en `0600`, con el contenido completo.
#[cfg(unix)]
fn crear_privado(ruta: &std::path::Path, contenido: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut archivo = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(ruta)?;
    archivo.write_all(contenido)?;
    archivo.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn reemplazar(origen: &std::path::Path, destino: &std::path::Path) -> anyhow::Result<()> {
    std::fs::rename(origen, destino)?;
    Ok(())
}

/// Crea `ruta` (no debe existir) con una DACL protegida que da acceso total
/// sólo al dueño (`D:P(A;;FA;;;OW)`: sin herencia de la carpeta), en la misma
/// llamada que lo crea.
#[cfg(windows)]
fn crear_privado(ruta: &std::path::Path, contenido: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use windows::Win32::Foundation::{GENERIC_WRITE, HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
    use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows::Win32::Storage::FileSystem::{CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE};
    use windows::core::PCWSTR;

    let sddl: Vec<u16> = "D:P(A;;FA;;;OW)".encode_utf16().chain(std::iter::once(0)).collect();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: SDDL terminado en 0; el descriptor se libera con `LocalFree` abajo.
    unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(sddl.as_ptr()), SDDL_REVISION_1, &mut descriptor, None) }?;
    let atributos = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: false.into(),
    };
    let nombre: Vec<u16> = ruta.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    // SAFETY: nombre terminado en 0 y atributos válidos durante la llamada.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(nombre.as_ptr()),
            GENERIC_WRITE.0,
            FILE_SHARE_NONE,
            Some(&atributos),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    };
    // SAFETY: `CreateFileW` ya copió el descriptor al objeto; no se usa más.
    unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
    let handle = handle?;
    // SAFETY: handle de archivo propio y válido; `File` lo cierra al soltarse.
    let mut archivo = unsafe { std::fs::File::from_raw_handle(handle.0) };
    archivo.write_all(contenido)?;
    archivo.sync_all()?;
    Ok(())
}

/// `rename` de std sobre un destino existente usa `MoveFileExW` con
/// `MOVEFILE_REPLACE_EXISTING`: el archivo nuevo (con su ACL propia)
/// reemplaza al viejo.
#[cfg(windows)]
fn reemplazar(origen: &std::path::Path, destino: &std::path::Path) -> anyhow::Result<()> {
    std::fs::rename(origen, destino)?;
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
    let datos = std::fs::read(&ruta).map_err(|_| anyhow::anyhow!("no hay perfil local — corré `ellkan-cli register` primero"))?;
    Ok(serde_json::from_slice(&datos)?)
}

pub fn guardar_sesion(sesion: &Sesion) -> anyhow::Result<()> {
    let ruta = ruta_sesion()?;
    escribir_archivo_privado(&ruta, &serde_json::to_vec_pretty(sesion)?)?;
    Ok(())
}

pub fn cargar_sesion() -> anyhow::Result<Sesion> {
    let ruta = ruta_sesion()?;
    let datos = std::fs::read(&ruta).map_err(|_| anyhow::anyhow!("no hay sesión activa — corré `ellkan-cli login` primero"))?;
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

        // QA-46: un `sesion.json` de una versión vieja, legible por todos,
        // queda en 0600 al volver a guardarlo.
        std::fs::set_permissions(dir.join("sesion.json"), std::fs::Permissions::from_mode(0o644)).unwrap();
        guardar_sesion(&Sesion { session_id: uuid::Uuid::now_v7() }).unwrap();
        let permisos = std::fs::metadata(dir.join("sesion.json")).unwrap().permissions();
        assert_eq!(permisos.mode() & 0o777, 0o600);
        let carpeta = std::fs::metadata(&dir).unwrap().permissions();
        assert_eq!(carpeta.mode() & 0o777, 0o700);

        unsafe { std::env::remove_var("ELLKAN_CONFIG_DIR") };
        std::fs::remove_dir_all(&dir).ok();
    }
}
