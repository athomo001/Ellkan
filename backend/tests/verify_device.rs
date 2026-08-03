// Autor: Athan Espinoza

//! Cobertura dedicada de F-02 (verify-device) — checklist de seguridad
//! aplicado explícitamente: código incorrecto rechazado, nada en claro en
//! `device_challenges`/`outbound_emails` salvo el cuerpo del email (que
//! legítimamente lo necesita), y un dispositivo ya conocido no vuelve a pedir
//! verificación en el login siguiente.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::Signer;
use ellkan_crypto::claves::{KeypairAcuerdo, KeypairFirma};
use ellkan_crypto::clave_privada;
use ellkan_crypto::secretos::PassphraseSecreta;
use secrecy::SecretBox;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt};

/// El consumidor de eventos que encola el email corre en su propia tarea
/// tokio, desacoplada del request que la dispara — bajo carga (varios tests
/// con Postgres en paralelo) puede no haber escrito la fila todavía en el
/// instante exacto en que el test la busca, así que se reintenta brevemente.
async fn esperar_email(pool: &sqlx::PgPool, email: &str) -> String {
    for _ in 0..20 {
        if let Ok((body,)) = sqlx::query_as::<_, (String,)>(
            "select body from outbound_emails where recipient = $1 order by created_at desc limit 1",
        )
        .bind(email)
        .fetch_one(pool)
        .await
        {
            return body;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("debería haber un email encolado para {email} tras reintentar");
}

struct Contexto {
    base: String,
    cliente: reqwest::Client,
    pool: sqlx::PgPool,
    // Se mantiene vivo mientras dure el test — al dropearse, `testcontainers`
    // para y borra el contenedor. Nunca se descarta con `mem::forget`.
    _contenedor: ContainerAsync<Postgres>,
}

async fn levantar() -> Contexto {
    let contenedor = Postgres::default()
        .with_db_name("ellkan")
        .with_user("postgres")
        .with_password("postgres")
        .with_tag("18")
        .start()
        .await
        .expect("levantar Postgres 18 en un contenedor");

    let puerto = contenedor.get_host_port_ipv4(5432).await.unwrap();
    let database_url = format!("postgres://postgres:postgres@127.0.0.1:{puerto}/ellkan");
    let estado = ellkan_backend::construir_estado(&database_url).await.expect("migrar y conectar");
    let pool = estado.pool.clone();
    let app = ellkan_backend::construir_router(estado);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await
            .unwrap();
    });

    Contexto {
        base: format!("http://{addr}"),
        cliente: reqwest::Client::new(),
        pool,
        _contenedor: contenedor,
    }
}

struct Usuario {
    email: String,
    ed25519: KeypairFirma,
    device_token: [u8; 32],
}

async fn registrar(ctx: &Contexto, email: &str) -> Usuario {
    let x25519 = KeypairAcuerdo::generar();
    let ed25519 = KeypairFirma::generar();
    let passphrase: PassphraseSecreta = SecretBox::new(Box::new("passphrase-de-prueba-larga".to_string()));
    let mut privadas = [0u8; 64];
    privadas[..32].copy_from_slice(x25519.privada().to_bytes().as_slice());
    privadas[32..].copy_from_slice(&ed25519.firmante().to_bytes());
    let salt: [u8; 16] = ellkan_crypto::aleatoriedad::bytes_aleatorios();
    let blob = clave_privada::cifrar_clave_privada(&passphrase, salt, &privadas, email.as_bytes()).unwrap();

    let resp = ctx
        .cliente
        .post(format!("{}/auth/register", ctx.base))
        .json(&json!({
            "email": email,
            "display_name": email,
            "public_key_x25519_b64": B64.encode(x25519.publica().as_bytes()),
            "public_key_ed25519_b64": B64.encode(ed25519.verificadora().to_bytes()),
            "encrypted_private_key_blob_b64": B64.encode(&blob.envoltura.ciphertext),
            "private_key_nonce_b64": B64.encode(blob.envoltura.nonce),
            "kdf_salt_b64": B64.encode(blob.salt),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let device_token: [u8; 32] = ellkan_crypto::aleatoriedad::bytes_aleatorios();
    Usuario { email: email.to_string(), ed25519, device_token }
}

/// Un `verify` completo (firma correcta) — devuelve el cuerpo JSON crudo para
/// que cada test decida qué hacer con `estado`.
async fn intentar_verify(ctx: &Contexto, usuario: &Usuario) -> Value {
    let resp = ctx
        .cliente
        .post(format!("{}/auth/challenge", ctx.base))
        .json(&json!({ "email": usuario.email }))
        .send()
        .await
        .unwrap();
    let cuerpo: Value = resp.json().await.unwrap();
    let nonce = B64.decode(cuerpo["nonce_b64"].as_str().unwrap()).unwrap();
    let firma = usuario.ed25519.firmante().sign(&nonce);
    let device_token_hash_b64 = B64.encode(Sha256::digest(usuario.device_token));

    let resp = ctx
        .cliente
        .post(format!("{}/auth/verify", ctx.base))
        .json(&json!({
            "email": usuario.email,
            "nonce_b64": B64.encode(&nonce),
            "signature_b64": B64.encode(firma.to_bytes()),
            "device_token_hash_b64": device_token_hash_b64,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    resp.json().await.unwrap()
}

#[tokio::test]
async fn codigo_incorrecto_es_rechazado_y_no_consume_el_desafio() {
    let ctx = levantar().await;
    let usuario = registrar(&ctx, "device-mal-codigo@test.ellkan").await;

    let cuerpo = intentar_verify(&ctx, &usuario).await;
    assert_eq!(cuerpo["estado"], "pendiente_dispositivo");
    let device_challenge_id = cuerpo["device_challenge_id"].as_str().unwrap();

    let resp = ctx
        .cliente
        .post(format!("{}/auth/verify-device", ctx.base))
        .json(&json!({ "device_challenge_id": device_challenge_id, "code": "000000" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "un código incorrecto nunca debe emitir sesión");
}

#[tokio::test]
async fn ningun_codigo_en_claro_queda_en_device_challenges() {
    let ctx = levantar().await;
    let usuario = registrar(&ctx, "device-sin-fuga@test.ellkan").await;

    let cuerpo = intentar_verify(&ctx, &usuario).await;
    assert_eq!(cuerpo["estado"], "pendiente_dispositivo");

    let body = esperar_email(&ctx.pool, &usuario.email).await;
    let codigo = body.lines().find_map(|l| l.strip_prefix("Código de verificación: ")).unwrap().trim().to_string();

    // El código SÍ aparece en el cuerpo del email (es lo que se manda) —
    // pero NUNCA en `device_challenges.code_hash`.
    let (code_hash,): (Vec<u8>,) =
        sqlx::query_as("select code_hash from device_challenges where user_id = (select id from users where email = $1)")
            .bind(&usuario.email)
            .fetch_one(&ctx.pool)
            .await
            .unwrap();
    let como_texto = String::from_utf8_lossy(&code_hash);
    assert!(!como_texto.contains(&codigo), "code_hash nunca debe contener el código en claro");
}

#[tokio::test]
async fn dispositivo_ya_conocido_no_vuelve_a_pedir_verificacion() {
    let ctx = levantar().await;
    let usuario = registrar(&ctx, "device-ya-conocido@test.ellkan").await;

    // Primer login: pendiente -> se resuelve con el código emailado (stub).
    let cuerpo = intentar_verify(&ctx, &usuario).await;
    assert_eq!(cuerpo["estado"], "pendiente_dispositivo");
    let device_challenge_id = cuerpo["device_challenge_id"].as_str().unwrap();
    let body = esperar_email(&ctx.pool, &usuario.email).await;
    let codigo = body.lines().find_map(|l| l.strip_prefix("Código de verificación: ")).unwrap().trim().to_string();

    let resp = ctx
        .cliente
        .post(format!("{}/auth/verify-device", ctx.base))
        .json(&json!({ "device_challenge_id": device_challenge_id, "code": codigo }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Segundo login, mismo device_token -> ahora debe ser "completo" directo.
    let cuerpo = intentar_verify(&ctx, &usuario).await;
    assert_eq!(cuerpo["estado"], "completo", "el dispositivo ya quedó marcado como conocido");
    assert!(cuerpo["session_id"].is_string());
}
