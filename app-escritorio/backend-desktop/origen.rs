// Autor: Athan Espinoza

//! Quién puede hablar con el backend local. Escucha sólo en loopback, pero
//! "sólo loopback" no alcanza: cualquier página web abierta en el navegador
//! del usuario puede hacer `fetch("http://127.0.0.1:<puerto>/…")`, y con un
//! CORS abierto a todos los orígenes leería la respuesta. Y con *DNS
//! rebinding* (un dominio del atacante que resuelve a 127.0.0.1) la página
//! hasta sería "mismo origen" para el navegador.
//!
//! Dos comprobaciones, las dos necesarias (spec/13 §15):
//! - **`Origin`**: si viene, tiene que ser la propia app (WebView), una
//!   extensión de navegador o —sólo en desarrollo— el servidor de Vite. Si no
//!   viene (cliente que no es un navegador: el helper de SSH, `curl`, las
//!   pruebas) se deja pasar: un navegador siempre lo manda en un POST.
//! - **`Host`**: tiene que ser loopback. Es lo que corta el DNS rebinding, en
//!   el que el `Host` es el dominio del atacante.
//!
//! Son funciones puras para probarlas sin levantar nada.

/// ¿Puede este `Origin` llamar al backend local?
pub fn origen_permitido(origen: &str) -> bool {
    // La app embebida. WebView2 (Windows) sirve el frontend como
    // `http://tauri.localhost`; WebKit (macOS/Linux) como `tauri://localhost`.
    const APP: &[&str] = &["tauri://localhost", "http://tauri.localhost", "https://tauri.localhost"];
    if APP.contains(&origen) {
        return true;
    }

    // Extensiones de navegador. Su id no se puede fijar (una extensión cargada
    // sin empaquetar tiene un id que depende de la carpeta), y son código que
    // el usuario instaló con más permisos que cualquier página.
    for esquema in ["chrome-extension://", "moz-extension://", "safari-web-extension://"] {
        if let Some(id) = origen.strip_prefix(esquema) {
            return !id.is_empty() && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
        }
    }

    // El servidor de Vite de `pnpm tauri dev`, sólo en builds de debug.
    cfg!(debug_assertions) && ["http://localhost:5173", "http://127.0.0.1:5173"].contains(&origen)
}

/// ¿Es este `Host` una dirección de loopback (con o sin puerto)? Un dominio
/// que sólo *empieza* con `127.0.0.1` (`127.0.0.1.malo.com`) no cuenta.
pub fn host_permitido(host: &str) -> bool {
    let sin_puerto = match host.strip_prefix('[') {
        // IPv6 entre corchetes: `[::1]:8080`
        Some(resto) => resto.split(']').next().unwrap_or(""),
        None => host.rsplit_once(':').map_or(host, |(nombre, _)| nombre),
    };
    matches!(sin_puerto.to_ascii_lowercase().as_str(), "127.0.0.1" | "localhost" | "::1")
}
