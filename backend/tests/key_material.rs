// Autor: Athan Espinoza

//! QA-03/QA-15: el blob de la clave privada sólo se entrega a quien prueba
//! la `auth_key` (derivada del mismo Argon2id que lo abre), y ni el prelogin
//! ni el rechazo delatan si una cuenta existe. Las cuentas selladas antes de
//! QA-03 siguen abriendo y se re-sellan con `POST /me/kdf-upgrade`.

mod common;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::Signer;
use ellkan_crypto::clave_privada;
use ellkan_crypto::derivacion::ParametrosKdf;
use secrecy::ExposeSecret;
use serde_json::{Value, json};

async fn key_material(entorno: &common::Entorno, cuerpo: Value) -> reqwest::Response {
    entorno
        .cliente
        .post(format!("{}/auth/key-material", entorno.base))
        .json(&cuerpo)
        .send()
        .await
        .unwrap()
}

fn privadas_de(u: &common::Usuario) -> [u8; 64] {
    let mut privadas = [0u8; 64];
    privadas[..32].copy_from_slice(u.x25519.privada().to_bytes().as_slice());
    privadas[32..].copy_from_slice(&u.ed25519.firmante().to_bytes());
    privadas
}

#[tokio::test]
async fn el_blob_se_entrega_solo_contra_la_auth_key_y_sin_delatar_cuentas() {
    let entorno = common::levantar().await;
    let usuario = common::registrar(&entorno, "real-key-material@test.ellkan").await;

    // Prelogin: el de un email inexistente tiene la forma del real, es estable
    // y distinto entre emails.
    let real = common::prelogin(&entorno, &usuario.email).await;
    let falso_1 = common::prelogin(&entorno, "nadie-key-material@test.ellkan").await;
    let falso_2 = common::prelogin(&entorno, "nadie-key-material@test.ellkan").await;
    let otro_falso = common::prelogin(&entorno, "otro-nadie@test.ellkan").await;
    assert_eq!(falso_1, falso_2, "dos consultas por el mismo email inexistente deben ser idénticas");
    assert_ne!(falso_1["kdf_salt_b64"], otro_falso["kdf_salt_b64"], "emails distintos no comparten sal");
    for p in [&real, &falso_1] {
        assert_eq!(B64.decode(p["kdf_salt_b64"].as_str().unwrap()).unwrap().len(), 16);
        assert_eq!(p["kdf_params"], json!(ParametrosKdf::ACTUAL));
        assert_eq!(p["auth_key_required"], true);
    }

    // Sin auth_key, con una equivocada, o para un email sin cuenta: el mismo 401.
    let mut cuerpos_401 = Vec::new();
    for cuerpo in [
        json!({ "email": usuario.email }),
        json!({ "email": usuario.email, "auth_key_b64": B64.encode([9u8; 32]) }),
        json!({ "email": "nadie-key-material@test.ellkan" }),
        json!({ "email": "nadie-key-material@test.ellkan", "auth_key_b64": B64.encode([9u8; 32]) }),
    ] {
        let resp = key_material(&entorno, cuerpo).await;
        assert_eq!(resp.status(), 401);
        // `request_id` cambia en cada request: se compara el resto.
        let mut cuerpo: Value = resp.json().await.unwrap();
        cuerpo["error"].as_object_mut().unwrap().remove("request_id");
        cuerpos_401.push(cuerpo);
    }
    assert!(cuerpos_401.windows(2).all(|w| w[0] == w[1]), "el rechazo no distingue los casos: {cuerpos_401:?}");

    // Con la auth_key correcta, el blob, y abre con la passphrase.
    let resp = common::key_material_con_passphrase(&entorno, &usuario.email, &usuario.passphrase).await;
    assert_eq!(resp.status(), 200);
    let material: Value = resp.json().await.unwrap();
    let blob = clave_privada::EncryptedPrivateKeyBlob {
        salt: B64.decode(material["kdf_salt_b64"].as_str().unwrap()).unwrap().try_into().unwrap(),
        parametros: serde_json::from_value(material["kdf_params"].clone()).unwrap(),
        envoltura: ellkan_crypto::aead::Envoltura {
            nonce: B64.decode(material["private_key_nonce_b64"].as_str().unwrap()).unwrap().try_into().unwrap(),
            ciphertext: B64.decode(material["encrypted_private_key_blob_b64"].as_str().unwrap()).unwrap(),
        },
    };
    let abierta = clave_privada::descifrar_clave_privada(&usuario.passphrase, &blob, usuario.email.as_bytes()).unwrap();
    assert_eq!(abierta.as_slice(), &privadas_de(&usuario));

    // El verificador guardado no es la auth_key.
    let (verificador,): (Vec<u8>,) = sqlx::query_as("select auth_verifier from user_keys where user_id = $1")
        .bind(usuario.user_id)
        .fetch_one(&entorno.pool)
        .await
        .unwrap();
    assert_eq!(verificador.len(), 32);
}

#[tokio::test]
async fn el_servidor_no_acepta_blobs_sellados_con_parametros_debiles() {
    let entorno = common::levantar().await;
    let resp = entorno
        .cliente
        .post(format!("{}/auth/register", entorno.base))
        .json(&json!({
            "email": "debil@test.ellkan",
            "display_name": "debil",
            "public_key_x25519_b64": B64.encode([1u8; 32]),
            "public_key_ed25519_b64": B64.encode([2u8; 32]),
            "encrypted_private_key_blob_b64": B64.encode([3u8; 80]),
            "private_key_nonce_b64": B64.encode([4u8; 24]),
            "kdf_salt_b64": B64.encode([5u8; 16]),
            "kdf_params": ParametrosKdf::LEGADO,
            "auth_key_b64": B64.encode([6u8; 32]),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

async fn mejorar_kdf(
    entorno: &common::Entorno,
    usuario: &common::Usuario,
    sesion: uuid::Uuid,
    sellada: &clave_privada::ClavePrivadaSellada,
) -> u16 {
    let blob = &sellada.blob;
    let privada = usuario.ed25519.firmante().to_bytes();
    let (challenge, firma) = common::prueba_de_posesion(entorno, &usuario.email, &privada, sellada).await;
    entorno
        .cliente
        .post(format!("{}/me/kdf-upgrade", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({
            "encrypted_private_key_blob_b64": B64.encode(&blob.envoltura.ciphertext),
            "private_key_nonce_b64": B64.encode(blob.envoltura.nonce),
            "kdf_salt_b64": B64.encode(blob.salt),
            "kdf_params": blob.parametros,
            "auth_key_b64": B64.encode(sellada.auth_key.expose_secret()),
            "challenge_nonce_b64": challenge,
            "signature_b64": firma,
        }))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

#[tokio::test]
async fn una_cuenta_sellada_antes_de_qa03_abre_y_se_re_sella_una_sola_vez() {
    let entorno = common::levantar().await;
    let usuario = common::registrar(&entorno, "legado@test.ellkan").await;
    let sesion = common::login(&entorno, &usuario).await;

    // Se lleva la cuenta al estado de antes de QA-03: blob con los
    // parámetros viejos y sin verificador.
    let privadas = privadas_de(&usuario);
    let viejo =
        clave_privada::cifrar_clave_privada(&usuario.passphrase, [3u8; 16], ParametrosKdf::LEGADO, &privadas, usuario.email.as_bytes())
            .unwrap()
            .blob;
    sqlx::query(
        "update user_keys set encrypted_private_key_blob = $2, private_key_nonce = $3, kdf_salt = $4,
                kdf_params = $5, auth_verifier = null where user_id = $1",
    )
    .bind(usuario.user_id)
    .bind(&viejo.envoltura.ciphertext)
    .bind(&viejo.envoltura.nonce[..])
    .bind(&viejo.salt[..])
    .bind(sqlx::types::Json(ParametrosKdf::LEGADO))
    .execute(&entorno.pool)
    .await
    .unwrap();

    let pre = common::prelogin(&entorno, &usuario.email).await;
    assert_eq!(pre["auth_key_required"], false);
    assert_eq!(pre["kdf_params"], json!(ParametrosKdf::LEGADO));
    let resp = key_material(&entorno, json!({ "email": usuario.email })).await;
    assert_eq!(resp.status(), 200, "la cuenta vieja sigue abriendo sin auth_key");

    // Re-sellado: misma passphrase, sal nueva, parámetros actuales, con la
    // prueba de posesión de siempre.
    let nueva =
        clave_privada::cifrar_clave_privada(&usuario.passphrase, [8u8; 16], ParametrosKdf::ACTUAL, &privadas, usuario.email.as_bytes())
            .unwrap();
    assert_eq!(mejorar_kdf(&entorno, &usuario, sesion, &nueva).await, 204);

    // Ya migrada: exige la auth_key, y la sesión sigue viva (la passphrase no cambió).
    let pre = common::prelogin(&entorno, &usuario.email).await;
    assert_eq!(pre["auth_key_required"], true);
    assert_eq!(pre["kdf_params"], json!(ParametrosKdf::ACTUAL));
    assert_eq!(key_material(&entorno, json!({ "email": usuario.email })).await.status(), 401);
    let resp = common::key_material_con_passphrase(&entorno, &usuario.email, &usuario.passphrase).await;
    assert_eq!(resp.status(), 200);
    let me = entorno.cliente.get(format!("{}/me", entorno.base)).bearer_auth(sesion).send().await.unwrap();
    assert_eq!(me.status(), 200, "la mejora no cierra sesiones");

    // Una sola vez: no sirve para cambiar la passphrase sin cerrar sesiones.
    assert_eq!(mejorar_kdf(&entorno, &usuario, sesion, &nueva).await, 409);

    // Sin la prueba de posesión, nada.
    let firma_ajena = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).sign(b"x");
    let resp = entorno
        .cliente
        .post(format!("{}/me/kdf-upgrade", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({
            "encrypted_private_key_blob_b64": B64.encode(&nueva.blob.envoltura.ciphertext),
            "private_key_nonce_b64": B64.encode(nueva.blob.envoltura.nonce),
            "kdf_salt_b64": B64.encode(nueva.blob.salt),
            "kdf_params": ParametrosKdf::ACTUAL,
            "auth_key_b64": B64.encode(nueva.auth_key.expose_secret()),
            "challenge_nonce_b64": B64.encode([1u8; 32]),
            "signature_b64": B64.encode(firma_ajena.to_bytes()),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn adivinar_la_auth_key_tiene_cupo_por_email() {
    let entorno = common::levantar().await;
    let mut estados = Vec::new();
    for _ in 0..12 {
        let resp = key_material(&entorno, json!({ "email": "Objetivo@test.ellkan", "auth_key_b64": B64.encode([9u8; 32]) })).await;
        estados.push(resp.status().as_u16());
    }
    assert_eq!(&estados[..10], &[401; 10]);
    assert_eq!(&estados[10..], &[429, 429], "pasado el cupo, 429 aunque la cuenta no exista");
    // El cupo es por email (normalizado), no global.
    let resp = key_material(&entorno, json!({ "email": "otro@test.ellkan" })).await;
    assert_eq!(resp.status(), 401);
    let resp = key_material(&entorno, json!({ "email": " objetivo@TEST.ellkan" })).await;
    assert_eq!(resp.status(), 429);
}
