// Autor: Athan Espinoza

//! "Conectar" desde la GUI (F-49): qué programa lanzar, con qué argumentos y
//! cómo entregarle el secreto para cada tipo de recurso. Es sólo el PLAN, sin
//! lanzar nada: así se puede probar sin abrir terminales ni clientes reales.
//! El shell (`src-tauri`) lo ejecuta.
//!
//! `host` y `usuario` vienen de los datos del usuario, que pueden traer texto
//! ajeno (un import CSV/KDBX, F-27): se validan ANTES de armar ningún
//! argumento. En particular un `host` que empiece con `-` se leería como una
//! opción del cliente (`ssh -oProxyCommand=…` ejecuta comandos), y nunca se
//! acepta.
//!
//! El secreto nunca va en la línea de comandos: `Inyeccion` dice por qué vía
//! se entrega (askpass, variable de entorno del proceso hijo, credencial de
//! Windows) o si no hay ninguna vía posible y hay que pegarlo (el cliente lo
//! pide él mismo).

/// Cómo llega la contraseña al cliente.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inyeccion {
    /// `SSH_ASKPASS`: `ssh` le pregunta al helper de Ellkan.
    Askpass,
    /// Variable de entorno del proceso hijo (nunca del de Ellkan).
    Entorno(&'static str),
    /// Credencial `TERMSRV/<host>` de Windows, que `mstsc` usa solo. Vive sólo
    /// en la sesión y se borra a los pocos segundos.
    CredencialRdp,
    /// El cliente pide la contraseña él mismo (o no tiene cómo recibirla): el
    /// frontend la deja en el portapapeles, con borrado automático.
    Portapapeles,
}

/// Dónde se abre el cliente.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ventana {
    /// Dentro de una terminal (Windows Terminal, o una consola nueva).
    Terminal,
    /// Cliente gráfico con su propia ventana (`mstsc`, un visor VNC).
    Propia,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Nombres de ejecutable a buscar, en orden de preferencia.
    pub programas: Vec<&'static str>,
    /// Mensaje si no se encontró ninguno.
    pub falta: &'static str,
    pub args: Vec<String>,
    pub inyeccion: Inyeccion,
    pub ventana: Ventana,
}

/// `Some(puerto)` por defecto de un tipo de recurso conectable.
pub fn puerto_por_defecto(tipo: &str) -> Option<u16> {
    Some(match tipo {
        "ssh" => 22,
        "ftp" => 21,
        "telnet" => 23,
        "vnc" => 5900,
        "rdp" => 3389,
        "postgresql" => 5432,
        "mysql" => 3306,
        "mongodb" => 27017,
        _ => return None,
    })
}

/// Un `host` aceptable: nombre de dominio, IPv4 o IPv6 (con o sin corchetes).
/// Sin espacios, sin caracteres de control ni de shell, y nunca empieza con
/// `-` (se leería como opción).
pub fn validar_host(host: &str) -> Result<(), String> {
    let ok = !host.is_empty()
        && host.len() <= 253
        && !host.starts_with('-')
        && host.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '[' | ']' | '%'));
    if ok {
        Ok(())
    } else {
        Err(format!("el host {host:?} no es válido para conectar (sólo letras, números, punto, guion y dos puntos)"))
    }
}

/// Un `usuario` aceptable: sin control ni saltos de línea, sin `-` inicial.
pub fn validar_usuario(usuario: &str) -> Result<(), String> {
    let ok = !usuario.is_empty()
        && usuario.len() <= 128
        && !usuario.starts_with('-')
        && !usuario.chars().any(|c| c.is_control() || c == '"' || c == '\'');
    if ok {
        Ok(())
    } else {
        Err(format!("el usuario {usuario:?} no es válido para conectar"))
    }
}

/// Arma el plan de conexión para `tipo`. `usuario` vacío se trata como "sin usuario".
pub fn planificar(tipo: &str, usuario: Option<&str>, host: &str, puerto: u16) -> Result<Plan, String> {
    validar_host(host)?;
    let usuario = usuario.filter(|u| !u.is_empty());
    if let Some(u) = usuario {
        validar_usuario(u)?;
    }
    let puerto_s = puerto.to_string();

    Ok(match tipo {
        "ssh" => {
            let objetivo = usuario.map_or_else(|| host.to_string(), |u| format!("{u}@{host}"));
            Plan {
                programas: vec!["ssh.exe"],
                falta: "no se encontró ssh.exe — activá el cliente OpenSSH en Windows (Configuración > Aplicaciones opcionales)",
                args: vec![objetivo, "-p".into(), puerto_s],
                inyeccion: Inyeccion::Askpass,
                ventana: Ventana::Terminal,
            }
        }
        // `ftp.exe` sólo acepta un host posicional (sin puerto): con el puerto
        // 21 abre directo; con otro, se lanza sin argumentos y el frontend le
        // dice al usuario que corra `open <host> <puerto>`.
        "ftp" => Plan {
            programas: vec!["ftp.exe"],
            falta: "no se encontró ftp.exe en el PATH",
            args: if puerto == 21 { vec![host.to_string()] } else { vec![] },
            inyeccion: Inyeccion::Portapapeles,
            ventana: Ventana::Terminal,
        },
        // Telnet no tiene usuario/contraseña a nivel de cliente: los pide el servidor.
        "telnet" => Plan {
            programas: vec!["telnet.exe"],
            falta: "no se encontró telnet.exe — activá el \"Cliente Telnet\" en Windows (Panel de control > Programas > Activar o desactivar características de Windows)",
            args: vec![host.to_string(), puerto_s],
            inyeccion: Inyeccion::Portapapeles,
            ventana: Ventana::Terminal,
        },
        // `host::puerto` (doble `:`) fuerza un puerto TCP explícito en TightVNC/RealVNC/UltraVNC.
        "vnc" => Plan {
            programas: vec!["vncviewer.exe", "tvnviewer.exe"],
            falta: "no se encontró ningún visor VNC instalado (TightVNC/RealVNC/UltraVNC) en el PATH",
            args: vec![format!("{host}::{puerto_s}")],
            inyeccion: Inyeccion::Portapapeles,
            ventana: Ventana::Propia,
        },
        // `mstsc` no acepta la contraseña por argumento: se le deja la
        // credencial `TERMSRV/<host>` de Windows y la usa sola.
        "rdp" => Plan {
            programas: vec!["mstsc.exe"],
            falta: "no se encontró mstsc.exe (Conexión a Escritorio remoto) en este Windows",
            args: vec![format!("/v:{host}:{puerto_s}")],
            inyeccion: Inyeccion::CredencialRdp,
            ventana: Ventana::Propia,
        },
        "postgresql" => {
            let mut args = vec!["-h".to_string(), host.to_string(), "-p".into(), puerto_s];
            if let Some(u) = usuario {
                args.extend(["-U".into(), u.to_string()]);
            }
            Plan {
                programas: vec!["psql.exe"],
                falta: "no se encontró psql.exe en el PATH — instalá las herramientas cliente de PostgreSQL",
                args,
                inyeccion: Inyeccion::Entorno("PGPASSWORD"),
                ventana: Ventana::Terminal,
            }
        }
        "mysql" => {
            let mut args = vec!["-h".to_string(), host.to_string(), "-P".into(), puerto_s];
            if let Some(u) = usuario {
                args.extend(["-u".into(), u.to_string()]);
            }
            Plan {
                programas: vec!["mysql.exe", "mariadb.exe"],
                falta: "no se encontró mysql.exe en el PATH — instalá el cliente de MySQL o MariaDB",
                args,
                inyeccion: Inyeccion::Entorno("MYSQL_PWD"),
                ventana: Ventana::Terminal,
            }
        }
        // `mongosh` no lee la contraseña de una variable de entorno y pasarla
        // con `--password` la dejaría en la línea de comandos: se abre con el
        // usuario y él la pide (el frontend deja la contraseña en el portapapeles).
        "mongodb" => {
            let autoridad = usuario.map_or_else(|| host.to_string(), |u| format!("{}@{host}", percent_codificar(u)));
            Plan {
                programas: vec!["mongosh.exe"],
                falta: "no se encontró mongosh.exe en el PATH — instalá MongoDB Shell",
                args: vec![format!("mongodb://{autoridad}:{puerto_s}/")],
                inyeccion: Inyeccion::Portapapeles,
                ventana: Ventana::Terminal,
            }
        }
        otro => return Err(format!("Conectar no soporta el tipo de recurso '{otro}'")),
    })
}

/// Codifica un usuario para ponerlo dentro de una URI (`@`, `:`, `/`… lo
/// romperían).
fn percent_codificar(texto: &str) -> String {
    let mut salida = String::new();
    for byte in texto.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            salida.push(byte as char);
        } else {
            salida.push_str(&format!("%{byte:02X}"));
        }
    }
    salida
}
