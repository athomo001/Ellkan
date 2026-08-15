// Autor: Athan Espinoza

//! Test de integración de la Fase 0 (Postgres real vía `testcontainers`,
//! nunca mockeado): dos usuarios se registran, el primero crea un recurso,
//! lo comparte, y el segundo lo lee — más una verificación explícita de que
//! ningún secreto viaja ni se guarda en claro.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::Signer;
use ellkan_crypto::aead::{self, Envoltura};
use ellkan_crypto::claves::{KeypairAcuerdo, KeypairFirma};
use ellkan_crypto::clave_privada;
use ellkan_crypto::secretos::PassphraseSecreta;
use ellkan_crypto::sellado;
use secrecy::{ExposeSecret, SecretBox};

use serde_json::{json, Value};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::ImageExt;
use uuid::Uuid;

struct Usuario {
    email: String,
    user_id: Uuid,
    x25519: KeypairAcuerdo,
    ed25519: KeypairFirma,
    passphrase: PassphraseSecreta,
    device_token: [u8; 32],
}

async fn registrar(
    cliente: &reqwest::Client,
    base: &str,
    pool: &sqlx::PgPool,
    email: &str,
    passphrase_valor: &str,
) -> Usuario {
    let x25519 = KeypairAcuerdo::generar();
    let ed25519 = KeypairFirma::generar();
    let passphrase: PassphraseSecreta = SecretBox::new(Box::new(passphrase_valor.to_string()));

    let mut privadas = [0u8; 64];
    privadas[..32].copy_from_slice(x25519.privada().to_bytes().as_slice());
    privadas[32..].copy_from_slice(&ed25519.firmante().to_bytes());
    let salt: [u8; 16] = ellkan_crypto::aleatoriedad::bytes_aleatorios();
    let blob = clave_privada::cifrar_clave_privada(&passphrase, salt, &privadas, email.as_bytes()).unwrap();

    let resp = cliente
        .post(format!("{base}/auth/register"))
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
    let status = resp.status();
    let texto = resp.text().await.unwrap();
    assert_eq!(status, 200, "register debería devolver 200, body: {texto}");
    let cuerpo: Value = serde_json::from_str(&texto).unwrap();
    let user_id: Uuid = cuerpo["user_id"].as_str().unwrap().parse().unwrap();

    // F-24: sólo el primer registro de este contenedor nace bootstrap (ya
    // verificado); el segundo (bob, en el test de compartición) queda
    // pendiente de verificación de email — este helper simula "ya revisó
    // su casilla" en vez de forzar a este test a ejercitar ese flujo, que
    // ya cubre `self_registration.rs`.
    sqlx::query!("update users set email_verified_at = now() where id = $1", user_id)
        .execute(pool)
        .await
        .unwrap();

    let device_token: [u8; 32] = ellkan_crypto::aleatoriedad::bytes_aleatorios();
    Usuario { email: email.to_string(), user_id, x25519, ed25519, passphrase, device_token }
}

/// Extrae el código de 6 dígitos del cuerpo del email encolado — simula
/// "revisar la casilla", ya que el envío real de SMTP queda diferido a Fase 1
/// (stub en `notificaciones.rs`, ver decisión en el plan). El consumidor que
/// encola corre en su propia tarea tokio, desacoplada del request que la
/// dispara — bajo carga (varios tests con Postgres en paralelo) puede no
/// haber escrito la fila todavía en el instante exacto en que se la busca,
/// así que se reintenta brevemente en vez de fallar al primer miss.
// F-24: filtra por `subject` — `registrar()` ahora también encola un email
// de verificación de cuenta para bob (no es el bootstrap de este
// contenedor, alice ya existe), así que puede haber más de una fila para
// el mismo `recipient` (ver el comentario equivalente en `common/mod.rs`).
async fn codigo_de_verificacion_encolado(pool: &sqlx::PgPool, email: &str) -> String {
    let mut cuerpo = None;
    for _ in 0..20 {
        if let Ok(fila) = sqlx::query_as::<_, (String,)>(
            "select body from outbound_emails where recipient = $1 and subject = $2 order by created_at desc limit 1",
        )
        .bind(email)
        .bind("Ellkan: verificá este dispositivo nuevo")
        .fetch_one(pool)
        .await
        {
            cuerpo = Some(fila.0);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let cuerpo = cuerpo.expect("debería haber un email encolado para este usuario tras reintentar");

    cuerpo
        .lines()
        .find_map(|linea| linea.strip_prefix("Código de verificación: "))
        .expect("el cuerpo del email debería contener el código")
        .trim()
        .to_string()
}

/// Login completo: `verify` siempre da `pendiente_dispositivo` la primera vez
/// (el `device_token` recién generado nunca está en `known_devices`) — el
/// test "lee el email" (stub) y cierra con `verify-device`, igual que haría
/// la CLI real.
async fn login(cliente: &reqwest::Client, base: &str, pool: &sqlx::PgPool, usuario: &Usuario) -> Uuid {
    let resp = cliente
        .post(format!("{base}/auth/challenge"))
        .json(&json!({ "email": usuario.email }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cuerpo: Value = resp.json().await.unwrap();
    let nonce = B64.decode(cuerpo["nonce_b64"].as_str().unwrap()).unwrap();

    let firma = usuario.ed25519.firmante().sign(&nonce);

    use sha2::{Digest, Sha256};
    let device_token_hash_b64 = B64.encode(Sha256::digest(usuario.device_token));

    let resp = cliente
        .post(format!("{base}/auth/verify"))
        .json(&json!({
            "email": usuario.email,
            "nonce_b64": B64.encode(&nonce),
            "signature_b64": B64.encode(firma.to_bytes()),
            "device_token_hash_b64": device_token_hash_b64,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "verify debería aceptar una firma válida");
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(
        cuerpo["estado"], "pendiente_dispositivo",
        "primer login desde un device_token nunca visto debe quedar pendiente"
    );
    let device_challenge_id = cuerpo["device_challenge_id"].as_str().unwrap();

    let codigo = codigo_de_verificacion_encolado(pool, &usuario.email).await;

    let resp = cliente
        .post(format!("{base}/auth/verify-device"))
        .json(&json!({ "device_challenge_id": device_challenge_id, "code": codigo }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let texto = resp.text().await.unwrap();
    assert_eq!(status, 200, "verify-device debería aceptar el código correcto, body: {texto}");
    let cuerpo: Value = serde_json::from_str(&texto).unwrap();
    cuerpo["session_id"].as_str().unwrap().parse().unwrap()
}

#[tokio::test]
async fn dos_usuarios_comparten_un_recurso_sin_fuga_de_secretos() {
    let _ = tracing_subscriber::fmt().with_env_filter("debug").try_init();

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

    let secrets_key: SecretBox<[u8; 32]> = SecretBox::new(Box::new(ellkan_crypto::aleatoriedad::bytes_aleatorios()));
    let estado = ellkan_backend::construir_estado(&database_url, secrets_key)
        .await
        .expect("migrar y conectar");
    let pool = estado.pool.clone();

    // Parte A/B: sin SMTP configurado, F-02 auto-verifica el dispositivo sin
    // pedir código — este test depende del flujo real (`pendiente_dispositivo`
    // + `verify-device`), mismo criterio que `common/mod.rs::levantar()`.
    sqlx::query!(
        r#"update smtp_config set host = 'smtp.invalid', port = 25, from_address = 'no-reply@ellkan.test' where organization_id = 1"#
    )
    .execute(&pool)
    .await
    .expect("seedear smtp_config para los tests");

    let app = ellkan_backend::construir_router(estado);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        // El rate limiter (PeerIpKeyExtractor) exige `SocketAddr` en las
        // extensions del request — mismo wiring que main.rs.
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });
    let base = format!("http://{addr}");
    let cliente = reqwest::Client::new();

    // --- Registro ---
    let alice = registrar(&cliente, &base, &pool, "alice@test.ellkan", "alice-passphrase-larga-1").await;
    let bob = registrar(&cliente, &base, &pool, "bob@test.ellkan", "bob-passphrase-larga-1").await;

    // --- Login (firma de nonce, F-02) ---
    let sesion_alice = login(&cliente, &base, &pool, &alice).await;
    let sesion_bob = login(&cliente, &base, &pool, &bob).await;

    // --- F-06 completo: un recurso compartible necesita metadata key
    // compartida — se promueve a Alice a admin (equivalente de test a
    // `ellkan-cli admin promote-to-admin`, F-41) sólo para poder crearla.
    sqlx::query("update users set role_id = (select id from roles where name = 'admin') where id = $1")
        .bind(alice.user_id)
        .execute(&pool)
        .await
        .unwrap();

    let metadata_key_publica = KeypairAcuerdo::generar();
    let metadata_key_id = Uuid::now_v7();
    let resp = cliente
        .post(format!("{base}/admin/metadata-keys"))
        .bearer_auth(sesion_alice)
        .json(&json!({
            "id": metadata_key_id,
            "public_key_x25519_b64": B64.encode(metadata_key_publica.publica().as_bytes()),
            "fingerprint": "test-fingerprint",
            "destinatarios": [],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "un admin puede crear la metadata key compartida");

    // --- Alice crea un recurso (todo cifrado client-side) ---
    let dek_bytes: [u8; 32] = ellkan_crypto::aleatoriedad::bytes_aleatorios();
    let dek_secreta = SecretBox::new(Box::new(dek_bytes));

    let resource_id = Uuid::now_v7();
    let mut aad = Vec::new();
    aad.extend_from_slice(resource_id.as_bytes());
    aad.extend_from_slice(alice.user_id.as_bytes());

    let metadata_plano = json!({ "name": "Cuenta banco", "username": "alice", "uri": "https://banco.test" });
    let secreto_plano = json!({ "password": "S3cr3t0-de-alice!", "notes": "cuenta corriente" });

    let metadata_env = aead::cifrar(&dek_secreta, &serde_json::to_vec(&metadata_plano).unwrap(), &aad).unwrap();
    let secreto_env = aead::cifrar(&dek_secreta, &serde_json::to_vec(&secreto_plano).unwrap(), &aad).unwrap();
    let sealed_dek_alice = sellado::sellar_dek(alice.x25519.publica(), &dek_secreta);

    let resp = cliente
        .post(format!("{base}/resources"))
        .bearer_auth(sesion_alice)
        .json(&json!({
            "id": resource_id,
            "resource_type_slug": "login-password",
            "metadata_ciphertext_b64": B64.encode(&metadata_env.ciphertext),
            "metadata_nonce_b64": B64.encode(metadata_env.nonce),
            "sealed_dek_b64": B64.encode(&sealed_dek_alice),
            "secret_ciphertext_b64": B64.encode(&secreto_env.ciphertext),
            "secret_nonce_b64": B64.encode(secreto_env.nonce),
            "metadata_key_id": metadata_key_id,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "crear recurso debería devolver 200");

    // --- Bob NO puede leerlo todavía ---
    let resp = cliente
        .get(format!("{base}/resources/{resource_id}/secret"))
        .bearer_auth(sesion_bob)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "sin compartir, Bob no debe tener acceso");

    // --- Alice comparte con Bob ---
    let publica_bob = *bob.x25519.publica();
    let sealed_dek_bob = sellado::sellar_dek(&publica_bob, &dek_secreta);
    let resp = cliente
        .post(format!("{base}/resources/{resource_id}/share"))
        .bearer_auth(sesion_alice)
        .json(&json!({
            "recipient_user_id": bob.user_id,
            "sealed_dek_b64": B64.encode(&sealed_dek_bob),
            "secret_ciphertext_b64": B64.encode(&secreto_env.ciphertext),
            "secret_nonce_b64": B64.encode(secreto_env.nonce),
            "level": "read",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "share debería aceptar el pedido del owner");

    // --- Bob lee el secreto y lo descifra correctamente ---
    let resp = cliente
        .get(format!("{base}/resources/{resource_id}/secret"))
        .bearer_auth(sesion_bob)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "tras compartir, Bob sí debe poder leer");
    let cuerpo: Value = resp.json().await.unwrap();
    let sealed_dek_bob_recibido = B64.decode(cuerpo["sealed_dek_b64"].as_str().unwrap()).unwrap();
    let secret_ciphertext_recibido = B64.decode(cuerpo["secret_ciphertext_b64"].as_str().unwrap()).unwrap();
    let secret_nonce_recibido: [u8; 24] =
        B64.decode(cuerpo["secret_nonce_b64"].as_str().unwrap()).unwrap().try_into().unwrap();

    let dek_de_bob = sellado::abrir_dek(bob.x25519.privada(), &sealed_dek_bob_recibido).unwrap();
    assert_eq!(dek_de_bob.expose_secret(), dek_secreta.expose_secret());

    let secreto_descifrado_bytes = aead::descifrar(
        &dek_de_bob,
        &Envoltura { nonce: secret_nonce_recibido, ciphertext: secret_ciphertext_recibido },
        &aad,
    )
    .unwrap();
    let secreto_descifrado: Value = serde_json::from_slice(&secreto_descifrado_bytes).unwrap();
    assert_eq!(secreto_descifrado["password"], "S3cr3t0-de-alice!");

    // --- El test de "esto es E2E de verdad": ningún secreto viaja/se guarda en claro ---
    // 1) La contraseña en claro nunca aparece en las filas persistidas.
    let filas_secreto: Vec<(Vec<u8>,)> =
        sqlx::query_as("select secret_ciphertext from secret_envelopes").fetch_all(&pool).await.unwrap();
    assert_eq!(filas_secreto.len(), 2, "una fila de secret_envelopes por usuario con acceso");
    for (ciphertext,) in &filas_secreto {
        let como_texto = String::from_utf8_lossy(ciphertext);
        assert!(
            !como_texto.contains("S3cr3t0-de-alice!"),
            "el ciphertext persistido no debe contener la contraseña en claro"
        );
    }
    // 2) La clave privada de ningún usuario quedó en claro en `user_keys`.
    let filas_claves: Vec<(Vec<u8>,)> =
        sqlx::query_as("select encrypted_private_key_blob from user_keys").fetch_all(&pool).await.unwrap();
    assert_eq!(filas_claves.len(), 2);
    for (blob,) in &filas_claves {
        assert_ne!(blob.as_slice(), alice.x25519.privada().to_bytes().as_slice());
        assert_ne!(blob.as_slice(), alice.ed25519.firmante().to_bytes().as_slice());
    }

    // Passphrases nunca se transmiten al servidor — no hay endpoint que las
    // reciba (comprobado por construcción del contrato: `RegisterRequest`/
    // `VerifyRequest` no tienen un campo de passphrase, ver backend/src/auth/dto.rs).
    let _ = &alice.passphrase;
    let _ = &bob.passphrase;
}
