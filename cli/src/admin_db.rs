// Autor: Athan Espinoza

//! F-28/F-41: comandos de mantenimiento con acceso **directo** a Postgres —
//! rompe a propósito el patrón "CLI = 100% cliente HTTP" del resto del
//! binario. Mismo nivel de confianza que el backup del sistema (spec
//! `03-api-contrato.md`): "quien puede ejecutar esto ya tiene control
//! total de la infraestructura, exponerlo por HTTP sólo agregaría
//! superficie de ataque sin ganar nada".

use std::path::Path;
use std::process::{Command, Stdio};

use sqlx::PgPool;
use uuid::Uuid;

pub fn database_url() -> anyhow::Result<String> {
    std::env::var("DATABASE_URL").map_err(|_| {
        anyhow::anyhow!(
            "falta DATABASE_URL — estos comandos necesitan acceso directo a Postgres, mismo nivel de confianza que un backup del sistema"
        )
    })
}

pub async fn conectar() -> anyhow::Result<PgPool> {
    Ok(PgPool::connect(&database_url()?).await?)
}

/// El resto de la CLI es síncrona (`reqwest::blocking`) — los comandos de
/// este módulo son la única excepción, cada uno abre su propio runtime de
/// un solo hilo en vez de convertir todo `main()` a async.
pub fn bloquear<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime tokio")
        .block_on(fut)
}

async fn auditar(
    pool: &PgPool,
    event_type: &str,
    subject_type: Option<&str>,
    subject_id: Option<Uuid>,
    metadata: serde_json::Value,
) -> anyhow::Result<()> {
    // `actor_user_id` va `null` literal (no bind) — F-41: "actor system-cli",
    // no atribuible a un `user_id` real (no hay sesión HTTP corriendo esto).
    sqlx::query!(
        r#"insert into audit_log_entries (actor_user_id, event_type, subject_type, subject_id, metadata)
           values (null, $1, $2, $3, $4)"#,
        event_type,
        subject_type,
        subject_id,
        metadata,
    )
    .execute(pool)
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------
// datacheck / cleanup
// ---------------------------------------------------------------------

pub struct FilaHuerfana {
    pub tabla: &'static str,
    pub id: Uuid,
    pub detalle: String,
}

/// F-41: `permissions.grantee_id` es la única columna verdaderamente
/// polimórfica sin FK real de todo el schema (documentado explícitamente
/// en `backend/migrations/0019_purge_usuario.sql`: "no tiene FK real —
/// columna polimórfica user/group"). El resto de las tablas ya tiene
/// integridad referencial forzada por Postgres (`references ... on delete
/// cascade/set null`), así que ahí no hay nada real que `datacheck` pueda
/// encontrar que la propia base no rechace de entrada — un `datacheck` que
/// "revisara" esas otras tablas sería teatro, no una verificación real.
pub async fn datacheck(pool: &PgPool) -> anyhow::Result<Vec<FilaHuerfana>> {
    let filas = sqlx::query!(
        r#"
        select p.id, p.grantee_type, p.grantee_id
        from permissions p
        where (p.grantee_type = 'user' and not exists (select 1 from users u where u.id = p.grantee_id))
           or (p.grantee_type = 'group' and not exists (select 1 from groups g where g.id = p.grantee_id))
        "#,
    )
    .fetch_all(pool)
    .await?;

    Ok(filas
        .into_iter()
        .map(|fila| FilaHuerfana {
            tabla: "permissions",
            id: fila.id,
            detalle: format!("grantee_type={} grantee_id={} no existe en la tabla correspondiente", fila.grantee_type, fila.grantee_id),
        })
        .collect())
}

async fn hay_algun_admin_activo(pool: &PgPool) -> anyhow::Result<bool> {
    let fila = sqlx::query!(
        r#"
        select exists(
            select 1 from users u
            join role_permissions rp on rp.role_id = u.role_id
            where rp.permission = '*' and u.active and u.deleted_at is null
        ) as "existe!"
        "#,
    )
    .fetch_one(pool)
    .await?;
    Ok(fila.existe)
}

/// Dry-run por default (sólo reporta lo que `datacheck` detectaría);
/// `fix=true` borra de verdad las filas huérfanas encontradas. Guard F-41
/// ("mismo verificado en Passbolt, `CleanupCommand::assertDatabaseState()`"):
/// con `fix=true` rehúsa correr si no queda ningún admin activo — el
/// dry-run no muta nada, así que no necesita el guard.
pub async fn cleanup(pool: &PgPool, fix: bool) -> anyhow::Result<Vec<FilaHuerfana>> {
    let huerfanas = datacheck(pool).await?;

    if fix {
        if !hay_algun_admin_activo(pool).await? {
            anyhow::bail!("cleanup --fix rehúsa correr: no queda ningún admin activo en la instancia");
        }
        if !huerfanas.is_empty() {
            let ids: Vec<Uuid> = huerfanas.iter().map(|h| h.id).collect();
            sqlx::query!("delete from permissions where id = any($1)", &ids).execute(pool).await?;
            auditar(
                pool,
                "cli.cleanup_ran",
                None,
                None,
                serde_json::json!({ "fixed": true, "orphans_removed": ids.len() }),
            )
            .await?;
        }
    }

    Ok(huerfanas)
}

// ---------------------------------------------------------------------
// promote-to-admin
// ---------------------------------------------------------------------

/// El break-glass real (F-41): promueve a un usuario a admin directo por
/// SQL, sin pasar por la API/UI — para "nos quedamos sin ningún admin
/// activo". Exige acceso directo al servidor, mismo nivel de confianza que
/// el backup (F-28): quien puede correr esto ya controla la instancia.
pub async fn promote_to_admin(pool: &PgPool, email: &str) -> anyhow::Result<Uuid> {
    let rol = sqlx::query!("select id from roles where name = 'admin'")
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| anyhow::anyhow!("no existe el rol 'admin' — instancia sin seed de roles (¿corrieron las migraciones?)"))?;

    let actualizado = sqlx::query!(
        "update users set role_id = $1 where email = $2 and deleted_at is null returning id",
        rol.id,
        email,
    )
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| anyhow::anyhow!("no existe un usuario activo (no eliminado) con email '{email}'"))?;

    auditar(pool, "cli.user_promoted", Some("user"), Some(actualizado.id), serde_json::json!({ "email": email })).await?;
    Ok(actualizado.id)
}

/// F-21: usada sólo por `admin create-user --role admin` — marca el
/// dispositivo de ESTE bootstrap (el perfil que `registrar()` acaba de
/// guardar en `~/.ellkan/`) como conocido, para que el primer `login` de
/// la cuenta recién creada no dependa de F-02 (código de verificación por
/// email) — exactamente lo que pide 01-requisitos-funcionales.md F-21:
/// bootstrap "sin depender de... que el email ya esté funcionando".
pub async fn marcar_dispositivo_conocido(pool: &PgPool, user_id: Uuid, device_token_hash: &[u8]) -> anyhow::Result<()> {
    sqlx::query!(
        "insert into known_devices (user_id, device_token_hash) values ($1, $2)
         on conflict (user_id, device_token_hash) do nothing",
        user_id,
        device_token_hash,
    )
    .execute(pool)
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------
// recover-setup
// ---------------------------------------------------------------------

pub enum EstadoRecoverySetup {
    NoExiste,
    YaRegistrado { user_id: Uuid, active: bool },
}

/// F-41 mapea directo al `recover_user` de Passbolt, que sí tiene sentido
/// ahí porque su registro es "el admin invita, la persona después completa
/// el setup con su propia passphrase" (un estado intermedio real). El
/// registro de Ellkan es atómico y 100% client-side (F-01): el cliente
/// genera su keypair y sube todo el material cifrado en un solo request —
/// no existe ningún estado "invitado, pendiente de configurar" en el
/// schema hoy (eso llegaría con F-24 self-registration, que no está
/// implementado todavía). Documentado acá en vez de fingir un mecanismo
/// que no existe: sin `--create` el comando sólo reporta si la cuenta ya
/// está completamente configurada (siempre lo está, si existe); con
/// `--create` sobre un email que no existe, falla explicando por qué no
/// puede "crear" nada sin la cooperación de esa persona.
pub async fn recover_setup(pool: &PgPool, email: &str, crear: bool) -> anyhow::Result<EstadoRecoverySetup> {
    let fila = sqlx::query!("select id, active from users where email = $1", email).fetch_optional(pool).await?;

    match fila {
        Some(f) => {
            if crear {
                auditar(
                    pool,
                    "cli.recovery_setup_issued",
                    Some("user"),
                    Some(f.id),
                    serde_json::json!({ "email": email, "outcome": "already_registered_no_pending_state" }),
                )
                .await?;
            }
            Ok(EstadoRecoverySetup::YaRegistrado { user_id: f.id, active: f.active })
        }
        None => {
            if crear {
                anyhow::bail!(
                    "no existe ningún usuario con email '{email}', y --create no puede generar la cuenta: el registro de Ellkan es atómico y 100% client-side (F-01) — no hay un estado 'invitado, pendiente de configurar' que este comando pueda completar sin la cooperación de esa persona. Alternativa real: 'ellkan-cli admin create-user' (bootstrap) y que la persona corra 'ellkan-cli register' con su propia passphrase."
                );
            }
            Ok(EstadoRecoverySetup::NoExiste)
        }
    }
}

// ---------------------------------------------------------------------
// send-test-email
// ---------------------------------------------------------------------

/// Verifica el pipeline interno (cola `outbound_emails` → poller) sin
/// disparar un flujo de negocio real sólo para probarlo — **no** valida un
/// relay SMTP real: ese envío sigue siendo el stub documentado desde Fase 0
/// (decisión explícita del usuario, ver `backend/src/notificaciones.rs`).
/// Cuando el poller deje de ser un stub, este mismo comando empieza a
/// verificar el envío real sin cambiar una línea.
pub async fn send_test_email(pool: &PgPool, destinatario: &str) -> anyhow::Result<bool> {
    sqlx::query!(
        r#"insert into outbound_emails (recipient, subject, body) values ($1, $2, $3)"#,
        destinatario,
        "Ellkan — email de prueba (ellkan-cli admin send-test-email)",
        "Generado por 'ellkan-cli admin send-test-email' para verificar la cola de notificaciones y el poller de envío.",
    )
    .execute(pool)
    .await?;

    for _ in 0..20 {
        let fila = sqlx::query!(
            r#"select status from outbound_emails where recipient = $1 order by created_at desc limit 1"#,
            destinatario,
        )
        .fetch_one(pool)
        .await?;
        if fila.status == "enviado" {
            return Ok(true);
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }
    Ok(false)
}

// ---------------------------------------------------------------------
// backup create / restore (F-28) — síncrono, no toca sqlx/tokio: shell-out
// a pg_dump/psql + streaming a través de `age`.
// ---------------------------------------------------------------------

/// Cifra el artefacto completo en streaming, nunca escribe un dump en claro
/// a disco ni siquiera transitoriamente — `pg_dump` escribe a un pipe,
/// leído directo hacia el `StreamWriter` de `age`, que escribe ciphertext
/// directo al archivo de salida. **Obligatorio, sin modo "sin cifrar"**:
/// `recipient_str` no tiene default en ningún nivel de este código, y un
/// `--recipient` vacío/ausente falla en el parseo de `clap`, antes de
/// llegar acá.
pub fn backup_create(database_url: &str, output_path: &Path, recipient_str: &str) -> anyhow::Result<()> {
    let resultado = backup_create_interno(database_url, output_path, recipient_str);
    if resultado.is_err() {
        // Cubre TODO camino de falla posterior a `File::create` (pg_dump
        // no encontrado, terminó con error, falla de E/S a mitad de
        // streaming) — sin esto, un `pg_dump` ausente dejaba un archivo
        // `.age` con sólo el header de `age` y nada más, que parece un
        // artefacto real pero nunca va a descifrar a nada útil.
        let _ = std::fs::remove_file(output_path);
    }
    resultado
}

fn backup_create_interno(database_url: &str, output_path: &Path, recipient_str: &str) -> anyhow::Result<()> {
    let recipient: age::x25519::Recipient =
        recipient_str.parse().map_err(|e| anyhow::anyhow!("clave pública de backup (age) inválida: {e}"))?;
    let encryptor = age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
        .map_err(|e| anyhow::anyhow!("no se pudo preparar el cifrado: {e}"))?;

    let salida = std::fs::File::create(output_path)
        .map_err(|e| anyhow::anyhow!("no se pudo crear '{}': {e}", output_path.display()))?;
    let mut writer = encryptor.wrap_output(salida)?;

    let mut hijo = Command::new("pg_dump")
        .arg(database_url)
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("no se pudo ejecutar pg_dump (¿está en PATH? paquete postgresql-client): {e}"))?;
    let mut stdout_hijo = hijo.stdout.take().expect("stdout redirigido a un pipe");
    std::io::copy(&mut stdout_hijo, &mut writer)?;
    writer.finish()?;

    let estado = hijo.wait()?;
    if !estado.success() {
        anyhow::bail!("pg_dump terminó con error (código {:?})", estado.code());
    }
    Ok(())
}

/// Descifra en streaming (nunca un archivo intermedio en claro) y lo
/// canaliza directo al stdin de `psql` — la clave privada de operaciones
/// vive fuera de la instancia, se aporta explícitamente en el momento del
/// restore (F-28: "Ellkan nunca la posee ni la almacena").
pub fn backup_restore(database_url: &str, input_path: &Path, identity_str: &str) -> anyhow::Result<()> {
    let identity: age::x25519::Identity =
        identity_str.parse().map_err(|e| anyhow::anyhow!("clave privada de backup (age) inválida: {e}"))?;

    let entrada = std::io::BufReader::new(
        std::fs::File::open(input_path).map_err(|e| anyhow::anyhow!("no se pudo abrir '{}': {e}", input_path.display()))?,
    );
    let decryptor =
        age::Decryptor::new_buffered(entrada).map_err(|e| anyhow::anyhow!("no se pudo leer el artefacto cifrado: {e}"))?;
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|_| anyhow::anyhow!("no se pudo descifrar — clave privada incorrecta o archivo corrupto"))?;

    let mut hijo = Command::new("psql")
        .arg(database_url)
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("no se pudo ejecutar psql (¿está en PATH? paquete postgresql-client): {e}"))?;
    {
        let mut stdin_hijo = hijo.stdin.take().expect("stdin redirigido a un pipe");
        std::io::copy(&mut reader, &mut stdin_hijo)?;
        // `stdin_hijo` se dropea acá (fin de este bloque), cerrando el pipe
        // — es la señal que `psql` necesita para saber que el input terminó.
    }

    let estado = hijo.wait()?;
    if !estado.success() {
        anyhow::bail!("psql (restore) terminó con error (código {:?})", estado.code());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    //! `pg_dump`/`psql` no están instalados en toda máquina de desarrollo
    //! (no lo están en la que escribió esto) — estos tests aíslan
    //! exactamente la parte que `backup_create`/`backup_restore` sí
    //! controlan por completo, la cadena de cifrado `age` en streaming,
    //! alimentándola con datos de prueba en vez de shellear a un binario
    //! externo. El plumbing de `Command`/pipes en sí (E/S estándar, sin
    //! lógica propia) queda documentado como no ejercitado en esta
    //! máquina en `docs/pendientesVerificacionReal.md`, no simulado acá.

    #[test]
    fn streaming_encrypt_decrypt_recupera_el_contenido_exacto() {
        let identity = age::x25519::Identity::generate();
        let recipient = identity.to_public();

        let contenido_de_prueba = b"contenido de prueba con acentos/\xc3\xb1: simula un dump de Postgres";

        let encryptor = age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient)).unwrap();
        let mut ciphertext = Vec::new();
        let mut writer = encryptor.wrap_output(&mut ciphertext).unwrap();
        std::io::Write::write_all(&mut writer, contenido_de_prueba).unwrap();
        writer.finish().unwrap();

        assert_ne!(ciphertext, contenido_de_prueba, "el artefacto debe ser ciphertext, no el contenido en claro");

        let decryptor = age::Decryptor::new_buffered(ciphertext.as_slice()).unwrap();
        let mut reader = decryptor.decrypt(std::iter::once(&identity as &dyn age::Identity)).unwrap();
        let mut recuperado = Vec::new();
        std::io::Read::read_to_end(&mut reader, &mut recuperado).unwrap();

        assert_eq!(recuperado, contenido_de_prueba);
    }

    #[test]
    fn identity_incorrecta_no_puede_descifrar() {
        let identity_real = age::x25519::Identity::generate();
        let recipient = identity_real.to_public();
        let identity_ajena = age::x25519::Identity::generate();

        let encryptor = age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient)).unwrap();
        let mut ciphertext = Vec::new();
        let mut writer = encryptor.wrap_output(&mut ciphertext).unwrap();
        std::io::Write::write_all(&mut writer, b"secreto de operaciones").unwrap();
        writer.finish().unwrap();

        let decryptor = age::Decryptor::new_buffered(ciphertext.as_slice()).unwrap();
        let resultado = decryptor.decrypt(std::iter::once(&identity_ajena as &dyn age::Identity));
        assert!(resultado.is_err(), "una identity que no es la del recipient nunca debe poder descifrar");
    }

    #[test]
    fn recipient_y_identity_hacen_roundtrip_por_su_representacion_en_texto() {
        // `backup create`/`restore` reciben la clave como string (`age1...`
        // / `AGE-SECRET-KEY-1...`), nunca como el tipo nativo — confirma
        // que el parseo desde texto (lo que realmente usan las funciones
        // públicas de este módulo) funciona igual que el tipo nativo.
        use secrecy::ExposeSecret;

        let identity = age::x25519::Identity::generate();
        let recipient_str = identity.to_public().to_string();
        let identity_str = identity.to_string().expose_secret().to_string();

        let recipient: age::x25519::Recipient = recipient_str.parse().unwrap();
        let identity_parseada: age::x25519::Identity = identity_str.parse().unwrap();

        let encryptor = age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient)).unwrap();
        let mut ciphertext = Vec::new();
        let mut writer = encryptor.wrap_output(&mut ciphertext).unwrap();
        std::io::Write::write_all(&mut writer, b"probando el camino de string, no el tipo nativo").unwrap();
        writer.finish().unwrap();

        let decryptor = age::Decryptor::new_buffered(ciphertext.as_slice()).unwrap();
        let mut reader = decryptor.decrypt(std::iter::once(&identity_parseada as &dyn age::Identity)).unwrap();
        let mut recuperado = Vec::new();
        std::io::Read::read_to_end(&mut reader, &mut recuperado).unwrap();

        assert_eq!(recuperado, b"probando el camino de string, no el tipo nativo");
    }
}
