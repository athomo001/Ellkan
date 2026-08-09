// Autor: Athan Espinoza

mod admin_db;
mod api;
mod config;
mod crypto_local;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use clap::{Parser, Subcommand};
use ellkan_crypto::clave_privada::EncryptedPrivateKeyBlob;
use secrecy::SecretBox;
use serde_json::json;
use uuid::Uuid;

use api::Cliente;
use ellkan_crypto::aead::Envoltura;

#[derive(Parser)]
#[command(name = "ellkan-cli", about = "CLI de Ellkan — F-21")]
struct Cli {
    /// Sobreescribe la URL del servidor (precedencia F-35: flag > env > perfil > default)
    #[arg(long, global = true)]
    server_url: Option<String>,

    /// Certificado de cliente para mTLS (F-35) — exige --client-key también, nunca uno sin el otro
    #[arg(long, global = true)]
    client_cert: Option<String>,
    /// Clave privada de cliente para mTLS (F-35) — exige --client-cert también
    #[arg(long, global = true)]
    client_key: Option<String>,
    /// CA bundle adicional para validar el servidor (mTLS opcional, F-35)
    #[arg(long, global = true)]
    ca_bundle: Option<String>,

    #[command(subcommand)]
    comando: Comando,
}

#[derive(Subcommand)]
enum Comando {
    /// Registra un usuario nuevo — genera los keypairs localmente (F-01)
    Register {
        #[arg(long)]
        email: String,
        #[arg(long)]
        display_name: String,
    },
    /// Login por firma de nonce (F-02) — guarda la sesión en ~/.ellkan/
    Login {
        #[arg(long)]
        email: String,
    },
    /// Crea un recurso login/password (F-05, F-06, F-07)
    Create {
        #[arg(long)]
        name: String,
        #[arg(long)]
        username: String,
        #[arg(long, default_value = "")]
        uri: String,
        #[arg(long)]
        password: String,
        #[arg(long, default_value = "")]
        notes: String,
    },
    /// Comparte un recurso con otro usuario (F-05, F-11 básico)
    Share {
        resource_id: Uuid,
        #[arg(long)]
        recipient_email: String,
        #[arg(long, default_value = "read")]
        level: String,
    },
    /// Descifra y muestra un recurso (metadata + secreto)
    Read { resource_id: Uuid },
    /// Lista los recursos visibles, descifrando metadata localmente; admite
    /// filtro tipo CEL (F-35) sobre name/username/uri/id/created_by
    List {
        /// Expresión CEL, ej: `name.contains("banco")`
        #[arg(long)]
        filter: Option<String>,
    },
    /// Ejecuta un comando con el password inyectado por variable de entorno
    /// al subproceso — nunca al entorno del shell padre (F-21)
    Exec {
        resource_id: Uuid,
        #[arg(long, default_value = "ELLKAN_PASSWORD")]
        env_var: String,
        #[arg(trailing_var_arg = true, required = true)]
        comando: Vec<String>,
    },
    /// Subcomandos de administración (F-41 básicos)
    Admin {
        #[command(subcommand)]
        accion: AdminAccion,
    },
}

#[derive(Subcommand)]
enum AdminAccion {
    /// Bootstrap del primer usuario/admin (01-requisitos-funcionales.md F-21) — sin
    /// `--role admin`, crea un usuario normal (mismo comportamiento de siempre).
    CreateUser {
        #[arg(long)]
        email: String,
        #[arg(long)]
        display_name: String,
        /// "user" (default) o "admin". Con "admin", promueve directo por SQL (necesita
        /// `DATABASE_URL`) y marca este mismo dispositivo como conocido — así el
        /// primer `login` de esta cuenta no depende de que el email ya funcione
        /// (F-02 se saltea sólo para este dispositivo puntual, exactamente lo que
        /// pide el spec: "sin depender de... que el email ya esté funcionando").
        #[arg(long, default_value = "user")]
        role: String,
    },
    Healthcheck,
    /// F-41: re-valida integridad de datos en modo sólo-lectura — reporta, no toca nada.
    /// Necesita `DATABASE_URL` (acceso directo a Postgres, ver `admin_db.rs`).
    Datacheck,
    /// F-41: dry-run por default (reporta lo que `datacheck` detectaría); `--fix` corrige
    /// de verdad. Rehúsa correr con `--fix` si no queda ningún admin activo.
    Cleanup {
        #[arg(long)]
        fix: bool,
    },
    /// F-41: el break-glass real — promueve a un usuario a admin directo por SQL, sin
    /// pasar por la API/UI, para "nos quedamos sin ningún admin activo".
    PromoteToAdmin {
        #[arg(long = "user")]
        email: String,
    },
    /// F-41: recupera/genera el setup inicial de una cuenta a medio onboarding — ver
    /// `admin_db::recover_setup` para la limitación real documentada (el registro de
    /// Ellkan es atómico, no hay estado "invitado, pendiente" que recuperar hoy).
    RecoverSetup {
        #[arg(long = "user")]
        email: String,
        #[arg(long)]
        create: bool,
    },
    /// F-41: verifica que la cola de notificaciones + el poller de envío funcionan de
    /// punta a punta, sin disparar un flujo de negocio real sólo para probarlo.
    SendTestEmail {
        #[arg(long)]
        to: String,
    },
    /// F-28: backup/restore cifrado del sistema completo — CLI-only, sin superficie REST.
    Backup {
        #[command(subcommand)]
        accion: BackupAccion,
    },
}

#[derive(Subcommand)]
enum BackupAccion {
    /// Cifrado obligatorio en streaming a una clave pública de operaciones (age) — sin
    /// clave configurada, falla explícitamente antes de tocar la base de datos.
    Create {
        #[arg(long)]
        output: std::path::PathBuf,
        /// Clave pública age del destinatario (`age1...`) — también se puede fijar vía
        /// `ELLKAN_BACKUP_RECIPIENT` para no tipearla en cada corrida (ej. cron).
        #[arg(long)]
        recipient: Option<String>,
    },
    /// Exige la clave privada de operaciones (`AGE-SECRET-KEY-1...`), que nunca vive en
    /// la instancia — se aporta manualmente en el momento del restore (F-28).
    Restore {
        #[arg(long)]
        input: std::path::PathBuf,
        #[arg(long)]
        identity: Option<String>,
    },
}

fn leer_passphrase(prompt: &str) -> anyhow::Result<SecretBox<String>> {
    if let Ok(valor) = std::env::var("ELLKAN_PASSPHRASE") {
        return Ok(SecretBox::new(Box::new(valor)));
    }
    let valor = rpassword::prompt_password(prompt)?;
    Ok(SecretBox::new(Box::new(valor)))
}

fn cliente_desde(cli: &Cli) -> anyhow::Result<Cliente> {
    let perfil = config::cargar_perfil().ok();
    let url = cli
        .server_url
        .clone()
        .unwrap_or_else(|| config::resolver_server_url(perfil.as_ref().map(|p| p.server_url.as_str())));

    let cert = cli
        .client_cert
        .clone()
        .or_else(|| config::resolver_client_cert(perfil.as_ref().and_then(|p| p.client_cert_path.as_deref())));
    let clave = cli
        .client_key
        .clone()
        .or_else(|| config::resolver_client_key(perfil.as_ref().and_then(|p| p.client_key_path.as_deref())));
    let ca = cli
        .ca_bundle
        .clone()
        .or_else(|| config::resolver_ca_bundle(perfil.as_ref().and_then(|p| p.ca_bundle_path.as_deref())));

    // F-35: mTLS es todo o nada — nunca cert sin key ni al revés.
    let mtls = match (cert, clave) {
        (Some(client_cert_path), Some(client_key_path)) => {
            Some(api::OpcionesMtls { client_cert_path, client_key_path, ca_bundle_path: ca })
        }
        (None, None) => None,
        _ => anyhow::bail!(
            "mTLS requiere --client-cert y --client-key juntos (F-35) — falta uno de los dos"
        ),
    };

    Cliente::nuevo(url, mtls)
}

#[allow(clippy::too_many_arguments)]
fn registrar(
    cliente: &Cliente,
    email: &str,
    display_name: &str,
    server_url: &str,
    client_cert_path: Option<String>,
    client_key_path: Option<String>,
    ca_bundle_path: Option<String>,
) -> anyhow::Result<()> {
    let passphrase = leer_passphrase("Passphrase nueva: ")?;
    let keypar = crypto_local::NuevoKeypar::generar();
    let blob = crypto_local::cifrar_para_registro(&keypar, &passphrase, email)?;

    let publica_x25519_b64 = B64.encode(keypar.x25519.publica().as_bytes());
    let publica_ed25519_b64 = B64.encode(keypar.ed25519.verificadora().to_bytes());
    let blob_b64 = B64.encode(&blob.envoltura.ciphertext);
    let nonce_b64 = B64.encode(blob.envoltura.nonce);
    let salt_b64 = B64.encode(blob.salt);

    let resp = cliente.register(
        email,
        display_name,
        &publica_x25519_b64,
        &publica_ed25519_b64,
        &blob_b64,
        &nonce_b64,
        &salt_b64,
    )?;

    // Token de dispositivo persistente (F-02) — se genera una sola vez acá,
    // sólo su hash viaja al backend en cada `login` futuro.
    let device_token_b64 = B64.encode(crypto_local::generar_device_token());

    config::guardar_perfil(&config::Perfil {
        server_url: server_url.to_string(),
        email: email.to_string(),
        user_id: resp.user_id,
        public_key_x25519_b64: publica_x25519_b64,
        public_key_ed25519_b64: publica_ed25519_b64,
        encrypted_private_key_blob_b64: blob_b64,
        private_key_nonce_b64: nonce_b64,
        kdf_salt_b64: salt_b64,
        client_cert_path,
        client_key_path,
        ca_bundle_path,
        device_token_b64: Some(device_token_b64),
    })?;

    println!("Usuario registrado: {}", resp.user_id);
    Ok(())
}

fn login(cliente: &Cliente, email: &str) -> anyhow::Result<()> {
    let mut perfil = config::cargar_perfil()?;
    let passphrase = leer_passphrase("Passphrase: ")?;

    let blob = blob_desde_perfil(&perfil)?;
    let clave = crypto_local::reconstruir_clave_privada(&passphrase, &blob, email)?;

    // Perfiles creados antes de F-02 no tienen device token todavía — se
    // genera acá una sola vez y se persiste, en vez de fallar.
    let device_token_b64 = match &perfil.device_token_b64 {
        Some(t) => t.clone(),
        None => {
            let nuevo = B64.encode(crypto_local::generar_device_token());
            perfil.device_token_b64 = Some(nuevo.clone());
            config::guardar_perfil(&perfil)?;
            nuevo
        }
    };
    let device_token = B64.decode(&device_token_b64)?;
    let device_token_hash_b64 = B64.encode(crypto_local::hash_device_token(&device_token));

    let challenge = cliente.challenge(email)?;
    let nonce = B64.decode(&challenge.nonce_b64)?;
    let firma = clave.firmar(&nonce);
    let firma_b64 = B64.encode(firma.to_bytes());

    let resp = cliente.verify(email, &challenge.nonce_b64, &firma_b64, &device_token_hash_b64)?;

    let session_id = match resp.estado.as_str() {
        "completo" => resp.session_id.ok_or_else(|| anyhow::anyhow!("respuesta de verify sin session_id"))?,
        "pendiente_dispositivo" => {
            let device_challenge_id = resp
                .device_challenge_id
                .ok_or_else(|| anyhow::anyhow!("respuesta de verify sin device_challenge_id"))?;
            println!("Dispositivo no reconocido — se envió un código por email.");
            let codigo = leer_codigo_dispositivo()?;
            cliente.verify_device(device_challenge_id, &codigo)?.session_id
        }
        otro => anyhow::bail!("estado de verify desconocido: {otro}"),
    };

    config::guardar_sesion(&config::Sesion { session_id })?;
    println!("Sesión iniciada: {session_id}");
    Ok(())
}

fn leer_codigo_dispositivo() -> anyhow::Result<String> {
    if let Ok(valor) = std::env::var("ELLKAN_DEVICE_CODE") {
        return Ok(valor);
    }
    Ok(rpassword::prompt_password("Código recibido por email: ")?)
}

fn blob_desde_perfil(perfil: &config::Perfil) -> anyhow::Result<EncryptedPrivateKeyBlob> {
    let ciphertext = B64.decode(&perfil.encrypted_private_key_blob_b64)?;
    let nonce_vec = B64.decode(&perfil.private_key_nonce_b64)?;
    let salt_vec = B64.decode(&perfil.kdf_salt_b64)?;
    let nonce: [u8; 24] = nonce_vec.try_into().map_err(|_| anyhow::anyhow!("nonce corrupto"))?;
    let salt: [u8; 16] = salt_vec.try_into().map_err(|_| anyhow::anyhow!("salt corrupto"))?;
    Ok(EncryptedPrivateKeyBlob { salt, envoltura: Envoltura { nonce, ciphertext } })
}

fn crear(
    cliente: &Cliente,
    name: &str,
    username: &str,
    uri: &str,
    password: &str,
    notes: &str,
) -> anyhow::Result<()> {
    let perfil = config::cargar_perfil()?;
    let sesion = config::cargar_sesion()?;

    let dek = crypto_local::generar_dek();
    // Generado client-side: el AAD (`resource_id` + `created_by`) se fija
    // antes de que la fila exista en el servidor — ver dto.rs del backend.
    let resource_id = Uuid::now_v7();
    let aad = crypto_local::aad_de_recurso(resource_id, perfil.user_id);

    let metadata = json!({ "name": name, "username": username, "uri": uri });
    let secreto = json!({ "password": password, "notes": notes });

    let metadata_env = crypto_local::cifrar_json(&dek, &metadata, &aad)?;
    let secreto_env = crypto_local::cifrar_json(&dek, &secreto, &aad)?;

    let publica_x25519: [u8; 32] = B64
        .decode(&perfil.public_key_x25519_b64)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("clave pública corrupta"))?;
    let sealed_dek = crypto_local::sellar_dek_para(&publica_x25519, &dek);

    let resp = cliente.crear_recurso(
        sesion.session_id,
        &api::CrearRecursoRequest {
            id: resource_id,
            resource_type_slug: "login-password".to_string(),
            metadata_ciphertext_b64: B64.encode(&metadata_env.ciphertext),
            metadata_nonce_b64: B64.encode(metadata_env.nonce),
            sealed_dek_b64: B64.encode(&sealed_dek),
            secret_ciphertext_b64: B64.encode(&secreto_env.ciphertext),
            secret_nonce_b64: B64.encode(secreto_env.nonce),
        },
    )?;

    println!("Recurso creado: {}", resp.id);
    Ok(())
}

/// Reconstruye la DEK en claro del recurso para el usuario autenticado —
/// helper compartido por `share`/`read`/`exec`.
fn abrir_dek_del_recurso(
    cliente: &Cliente,
    perfil: &config::Perfil,
    sesion: &config::Sesion,
    resource_id: Uuid,
    passphrase: &SecretBox<String>,
) -> anyhow::Result<(ellkan_crypto::secretos::ClaveSecreta32, api::SecretoResponse)> {
    let blob = blob_desde_perfil(perfil)?;
    let clave = crypto_local::reconstruir_clave_privada(passphrase, &blob, &perfil.email)?;
    let secreto = cliente.obtener_secreto(sesion.session_id, resource_id)?;
    let sealed_dek = B64.decode(&secreto.sealed_dek_b64)?;
    let dek = crypto_local::abrir_dek(&clave.x25519, &sealed_dek)?;
    Ok((dek, secreto))
}

fn compartir(cliente: &Cliente, resource_id: Uuid, recipient_email: &str, level: &str) -> anyhow::Result<()> {
    let perfil = config::cargar_perfil()?;
    let sesion = config::cargar_sesion()?;
    let passphrase = leer_passphrase("Passphrase (para abrir tu copia de la DEK): ")?;

    let (dek, secreto) = abrir_dek_del_recurso(cliente, &perfil, &sesion, resource_id, &passphrase)?;

    let destinatario = cliente.public_key(sesion.session_id, recipient_email)?;
    let publica_destinatario: [u8; 32] = B64
        .decode(&destinatario.public_key_x25519_b64)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("clave pública del destinatario corrupta"))?;

    let sealed_dek_destinatario = crypto_local::sellar_dek_para(&publica_destinatario, &dek);

    // Mismo ciphertext/nonce que ya tenía el dueño: mismo DEK + mismo nonce +
    // mismo plaintext ⇒ mismo ciphertext, sin volver a tocar el secreto en
    // claro ni exponerlo de nuevo (el servidor nunca lo ve tampoco acá).
    cliente.compartir(
        sesion.session_id,
        resource_id,
        &api::CompartirRequest {
            recipient_user_id: destinatario.user_id,
            sealed_dek_b64: B64.encode(&sealed_dek_destinatario),
            secret_ciphertext_b64: secreto.secret_ciphertext_b64,
            secret_nonce_b64: secreto.secret_nonce_b64,
            level: Some(level.to_string()),
        },
    )?;

    println!("Recurso {resource_id} compartido con {recipient_email} ({level})");
    Ok(())
}

fn leer(cliente: &Cliente, resource_id: Uuid) -> anyhow::Result<()> {
    let perfil = config::cargar_perfil()?;
    let sesion = config::cargar_sesion()?;
    let passphrase = leer_passphrase("Passphrase: ")?;

    let (dek, secreto) = abrir_dek_del_recurso(cliente, &perfil, &sesion, resource_id, &passphrase)?;
    let recurso = cliente.obtener_recurso(sesion.session_id, resource_id)?;

    // Mismo AAD fijo usado al crear (`resource_id` + `created_by` del dueño
    // original) — no depende de quién esté leyendo.
    let aad = crypto_local::aad_de_recurso(recurso.id, recurso.created_by);
    let metadata_nonce: [u8; 24] = B64
        .decode(&recurso.metadata_nonce_b64)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("metadata_nonce corrupto"))?;
    let metadata_ciphertext = B64.decode(&recurso.metadata_ciphertext_b64)?;
    let metadata = crypto_local::descifrar_json(
        &dek,
        &Envoltura { nonce: metadata_nonce, ciphertext: metadata_ciphertext },
        &aad,
    )?;

    let secret_nonce: [u8; 24] = B64
        .decode(&secreto.secret_nonce_b64)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("secret_nonce corrupto"))?;
    let secret_ciphertext = B64.decode(&secreto.secret_ciphertext_b64)?;
    let secreto_json = crypto_local::descifrar_json(
        &dek,
        &Envoltura { nonce: secret_nonce, ciphertext: secret_ciphertext },
        &aad,
    )?;

    println!("metadata: {metadata}");
    println!("secreto:  {secreto_json}");
    Ok(())
}

/// Lista los recursos visibles, descifrando metadata client-side (F-35:
/// filtro tipo CEL en vez de traer todo y filtrar en el script que llama a
/// la CLI). Los campos disponibles son los que hoy tiene la metadata —
/// `name`/`username`/`uri`/`id`/`created_by` — `tags` (el ejemplo
/// `tags.contains("prod")` de la spec) todavía no existe, es F-10 de Fase 1.
fn listar(cliente: &Cliente, filtro: Option<&str>) -> anyhow::Result<()> {
    let perfil = config::cargar_perfil()?;
    let sesion = config::cargar_sesion()?;
    let passphrase = leer_passphrase("Passphrase: ")?;

    let programa = filtro
        .map(cel_interpreter::Program::compile)
        .transpose()
        .map_err(|e| anyhow::anyhow!("expresión de filtro inválida: {e}"))?;

    let recursos = cliente.listar_recursos(sesion.session_id)?;
    for recurso in recursos {
        let (dek, _secreto) = abrir_dek_del_recurso(cliente, &perfil, &sesion, recurso.id, &passphrase)?;
        let aad = crypto_local::aad_de_recurso(recurso.id, recurso.created_by);
        let metadata_nonce: [u8; 24] = B64
            .decode(&recurso.metadata_nonce_b64)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("metadata_nonce corrupto"))?;
        let metadata_ciphertext = B64.decode(&recurso.metadata_ciphertext_b64)?;
        let metadata = crypto_local::descifrar_json(
            &dek,
            &Envoltura { nonce: metadata_nonce, ciphertext: metadata_ciphertext },
            &aad,
        )?;

        let coincide = match &programa {
            None => true,
            Some(programa) => {
                let mut contexto = cel_interpreter::Context::default();
                let campo = |clave: &str| metadata.get(clave).and_then(|v| v.as_str()).unwrap_or("").to_string();
                contexto.add_variable("name", campo("name"))?;
                contexto.add_variable("username", campo("username"))?;
                contexto.add_variable("uri", campo("uri"))?;
                contexto.add_variable("id", recurso.id.to_string())?;
                contexto.add_variable("created_by", recurso.created_by.to_string())?;
                matches!(programa.execute(&contexto)?, cel_interpreter::Value::Bool(true))
            }
        };

        if coincide {
            println!("{}  {}", recurso.id, metadata);
        }
    }
    Ok(())
}

fn ejecutar(cliente: &Cliente, resource_id: Uuid, env_var: &str, comando: &[String]) -> anyhow::Result<()> {
    let perfil = config::cargar_perfil()?;
    let sesion = config::cargar_sesion()?;
    let passphrase = leer_passphrase("Passphrase: ")?;

    let (dek, secreto) = abrir_dek_del_recurso(cliente, &perfil, &sesion, resource_id, &passphrase)?;
    let recurso = cliente.obtener_recurso(sesion.session_id, resource_id)?;
    let aad = crypto_local::aad_de_recurso(recurso.id, recurso.created_by);
    let secret_nonce: [u8; 24] = B64
        .decode(&secreto.secret_nonce_b64)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("secret_nonce corrupto"))?;
    let secret_ciphertext = B64.decode(&secreto.secret_ciphertext_b64)?;
    let secreto_json = crypto_local::descifrar_json(
        &dek,
        &Envoltura { nonce: secret_nonce, ciphertext: secret_ciphertext },
        &aad,
    )?;
    let password = secreto_json
        .get("password")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("el recurso no tiene campo 'password'"))?;

    // `.env()` sólo modifica el entorno del proceso hijo — nunca el del shell
    // padre, ni aparece en `ps`/argv (F-21, mismo patrón que go-passbolt-cli).
    let estado = std::process::Command::new(&comando[0])
        .args(&comando[1..])
        .env(env_var, password)
        .status()?;

    std::process::exit(estado.code().unwrap_or(1));
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let cliente = cliente_desde(&cli)?;
    let server_url_efectiva = cli
        .server_url
        .clone()
        .unwrap_or_else(|| config::resolver_server_url(None));

    match &cli.comando {
        Comando::Register { email, display_name } => registrar(
            &cliente,
            email,
            display_name,
            &server_url_efectiva,
            cli.client_cert.clone(),
            cli.client_key.clone(),
            cli.ca_bundle.clone(),
        )?,
        Comando::Login { email } => login(&cliente, email)?,
        Comando::Create { name, username, uri, password, notes } => {
            crear(&cliente, name, username, uri, password, notes)?
        }
        Comando::Share { resource_id, recipient_email, level } => {
            compartir(&cliente, *resource_id, recipient_email, level)?
        }
        Comando::Read { resource_id } => leer(&cliente, *resource_id)?,
        Comando::List { filter } => listar(&cliente, filter.as_deref())?,
        Comando::Exec { resource_id, env_var, comando } => ejecutar(&cliente, *resource_id, env_var, comando)?,
        Comando::Admin { accion } => match accion {
            AdminAccion::CreateUser { email, display_name, role } => {
                if role != "user" && role != "admin" {
                    anyhow::bail!("--role debe ser 'user' o 'admin', recibido '{role}'");
                }
                registrar(
                    &cliente,
                    email,
                    display_name,
                    &server_url_efectiva,
                    cli.client_cert.clone(),
                    cli.client_key.clone(),
                    cli.ca_bundle.clone(),
                )?;
                if role == "admin" {
                    // Ninguna ruta HTTP permite auto-asignarse admin — la
                    // promoción real siempre exige acceso directo a la base
                    // (mismo nivel de confianza que un backup del sistema),
                    // así que esto pasa por SQL igual que `promote-to-admin`,
                    // no por la API que `registrar()` acaba de usar.
                    let perfil = config::cargar_perfil()?;
                    let device_token_b64 = perfil
                        .device_token_b64
                        .clone()
                        .ok_or_else(|| anyhow::anyhow!("perfil recién creado sin device token — no debería pasar"))?;
                    let device_token = B64.decode(&device_token_b64)?;
                    let device_token_hash = crypto_local::hash_device_token(&device_token);
                    admin_db::bloquear(async {
                        let pool = admin_db::conectar().await?;
                        admin_db::promote_to_admin(&pool, email).await?;
                        admin_db::marcar_dispositivo_conocido(&pool, perfil.user_id, &device_token_hash).await?;
                        anyhow::Ok(())
                    })?;
                    println!(
                        "Promovido a admin — 'ellkan-cli login --email {email}' ya funciona ahora mismo, sin esperar ningún email (este dispositivo quedó marcado como conocido)."
                    );
                } else {
                    println!("Nota: usuario creado con rol 'user'. Para promoverlo a admin después, corré 'ellkan-cli admin promote-to-admin --user {email}'.");
                }
            }
            AdminAccion::Healthcheck => println!("{}", cliente.healthz()?),
            AdminAccion::Datacheck => admin_db::bloquear(async {
                let pool = admin_db::conectar().await?;
                let huerfanas = admin_db::datacheck(&pool).await?;
                if huerfanas.is_empty() {
                    println!("datacheck: sin filas huérfanas.");
                } else {
                    println!("datacheck: {} fila(s) huérfana(s) encontradas:", huerfanas.len());
                    for h in &huerfanas {
                        println!("  [{}] {} — {}", h.tabla, h.id, h.detalle);
                    }
                }
                anyhow::Ok(())
            })?,
            AdminAccion::Cleanup { fix } => admin_db::bloquear(async {
                let pool = admin_db::conectar().await?;
                let huerfanas = admin_db::cleanup(&pool, *fix).await?;
                if huerfanas.is_empty() {
                    println!("cleanup: nada que limpiar.");
                } else if *fix {
                    println!("cleanup --fix: {} fila(s) corregidas.", huerfanas.len());
                } else {
                    println!("cleanup (dry-run): {} fila(s) se corregirían con --fix:", huerfanas.len());
                    for h in &huerfanas {
                        println!("  [{}] {} — {}", h.tabla, h.id, h.detalle);
                    }
                }
                anyhow::Ok(())
            })?,
            AdminAccion::PromoteToAdmin { email } => admin_db::bloquear(async {
                let pool = admin_db::conectar().await?;
                let user_id = admin_db::promote_to_admin(&pool, email).await?;
                println!("'{email}' ({user_id}) promovido a admin.");
                anyhow::Ok(())
            })?,
            AdminAccion::RecoverSetup { email, create } => admin_db::bloquear(async {
                let pool = admin_db::conectar().await?;
                match admin_db::recover_setup(&pool, email, *create).await? {
                    admin_db::EstadoRecoverySetup::NoExiste => {
                        println!("'{email}' no tiene ninguna cuenta en Ellkan.");
                    }
                    admin_db::EstadoRecoverySetup::YaRegistrado { user_id, active } => {
                        println!(
                            "'{email}' ({user_id}) ya está completamente registrado (active={active}) — no hay ningún setup pendiente que recuperar."
                        );
                    }
                }
                anyhow::Ok(())
            })?,
            AdminAccion::SendTestEmail { to } => admin_db::bloquear(async {
                let pool = admin_db::conectar().await?;
                if admin_db::send_test_email(&pool, to).await? {
                    println!("OK: el email de prueba a '{to}' fue encolado y procesado por el poller.");
                } else {
                    println!(
                        "ADVERTENCIA: el email a '{to}' se encoló pero el poller no lo marcó 'enviado' a tiempo — revisá que el backend esté corriendo."
                    );
                }
                anyhow::Ok(())
            })?,
            AdminAccion::Backup { accion } => match accion {
                BackupAccion::Create { output, recipient } => {
                    let recipient = recipient
                        .clone()
                        .or_else(|| std::env::var("ELLKAN_BACKUP_RECIPIENT").ok())
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "no hay clave pública de backup configurada — pasá --recipient o seteá ELLKAN_BACKUP_RECIPIENT (F-28: sin esto, el comando rehúsa correr, no hay modo 'sin cifrar')"
                            )
                        })?;
                    let database_url = admin_db::database_url()?;
                    admin_db::backup_create(&database_url, output, &recipient)?;
                    println!("Backup cifrado escrito en '{}'.", output.display());
                }
                BackupAccion::Restore { input, identity } => {
                    let identity = identity.clone().ok_or_else(|| {
                        anyhow::anyhow!("--identity es obligatorio para restore (la clave privada de operaciones, nunca almacenada en la instancia)")
                    })?;
                    let database_url = admin_db::database_url()?;
                    admin_db::backup_restore(&database_url, input, &identity)?;
                    println!("Restore completado desde '{}'.", input.display());
                }
            },
        },
    }

    Ok(())
}
