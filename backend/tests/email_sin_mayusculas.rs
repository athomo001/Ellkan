// Autor: Athan Espinoza

//! QA-16: el email no distingue mayúsculas — una sola cuenta por email, el
//! login funciona como sea que se tipee, y `/auth/key-material` devuelve el
//! email guardado (AAD del blob) sin delatar si la cuenta existe.

mod common;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::Signer;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

async fn key_material(entorno: &common::Entorno, email: &str) -> Value {
    let resp = entorno
        .cliente
        .post(format!("{}/auth/key-material", entorno.base))
        .json(&json!({ "email": email }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    resp.json().await.unwrap()
}

#[tokio::test]
async fn una_cuenta_por_email_y_login_sin_importar_mayusculas() {
    let entorno = common::levantar().await;
    let alice = common::registrar(&entorno, "Alice@Test.Ellkan").await;

    // Mismo material como sea que se escriba, con el email guardado.
    let exacto = key_material(&entorno, "Alice@Test.Ellkan").await;
    let otro = key_material(&entorno, "  alice@test.ELLKAN ").await;
    assert_eq!(exacto, otro);
    assert_eq!(otro["email"], "Alice@Test.Ellkan");

    // Y abre con el email devuelto, no con el tipeado.
    let blob = ellkan_crypto::aead::Envoltura {
        nonce: B64.decode(otro["private_key_nonce_b64"].as_str().unwrap()).unwrap().try_into().unwrap(),
        ciphertext: B64.decode(otro["encrypted_private_key_blob_b64"].as_str().unwrap()).unwrap(),
    };
    let salt: [u8; 16] = B64.decode(otro["kdf_salt_b64"].as_str().unwrap()).unwrap().try_into().unwrap();
    let blob = ellkan_crypto::clave_privada::EncryptedPrivateKeyBlob { envoltura: blob, salt };
    assert!(ellkan_crypto::clave_privada::descifrar_clave_privada(&alice.passphrase, &blob, b"Alice@Test.Ellkan").is_ok());
    assert!(ellkan_crypto::clave_privada::descifrar_clave_privada(&alice.passphrase, &blob, b"alice@test.ellkan").is_err());

    // Sin cuenta: el material falso tampoco cambia con las mayúsculas, y el
    // email vuelve normalizado.
    let a = key_material(&entorno, "Nadie@Test.Ellkan").await;
    let b = key_material(&entorno, "nadie@test.ellkan").await;
    assert_eq!(a, b);
    assert_eq!(a["email"], "nadie@test.ellkan");

    // Login tipeando el email en minúsculas.
    let resp = entorno
        .cliente
        .post(format!("{}/auth/challenge", entorno.base))
        .json(&json!({ "email": "alice@test.ellkan" }))
        .send()
        .await
        .unwrap();
    let cuerpo: Value = resp.json().await.unwrap();
    let nonce = B64.decode(cuerpo["nonce_b64"].as_str().unwrap()).unwrap();
    let firma = alice.ed25519.firmante().sign(&nonce);
    let resp = entorno
        .cliente
        .post(format!("{}/auth/verify", entorno.base))
        .json(&json!({
            "email": "alice@test.ellkan",
            "nonce_b64": B64.encode(&nonce),
            "signature_b64": B64.encode(firma.to_bytes()),
            "device_token_hash_b64": B64.encode(Sha256::digest(alice.device_token)),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["estado"], "pendiente_dispositivo", "{cuerpo:?}");

    // Otra cuenta con el mismo email en otras mayúsculas: 409.
    let resp = entorno
        .cliente
        .post(format!("{}/auth/register", entorno.base))
        .json(&json!({
            "email": "ALICE@test.ellkan",
            "display_name": "otra",
            "public_key_x25519_b64": B64.encode([1u8; 32]),
            "public_key_ed25519_b64": B64.encode([2u8; 32]),
            "encrypted_private_key_blob_b64": B64.encode([3u8; 80]),
            "private_key_nonce_b64": B64.encode([4u8; 24]),
            "kdf_salt_b64": B64.encode([5u8; 16]),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
    let (cuentas,): (i64,) = sqlx::query_as("select count(*) from users where lower(email) = 'alice@test.ellkan'")
        .fetch_one(&entorno.pool)
        .await
        .unwrap();
    assert_eq!(cuentas, 1);
}

/// La migración 0059 se frena, con la lista, si ya hay emails que sólo
/// difieren en mayúsculas (base vieja, antes del índice).
#[tokio::test]
async fn la_migracion_se_frena_con_duplicados() {
    let entorno = common::levantar().await;
    sqlx::query("drop index users_email_lower_key").execute(&entorno.pool).await.unwrap();
    common::registrar(&entorno, "bob@test.ellkan").await;
    common::registrar(&entorno, "Bob@Test.Ellkan").await;

    let migracion = include_str!("../migrations/0059_email_sin_mayusculas.sql");
    let inicio = migracion.find("do $$").unwrap();
    let fin = migracion.find("$$;").unwrap() + 3;
    let error = sqlx::raw_sql(&migracion[inicio..fin]).execute(&entorno.pool).await.unwrap_err().to_string();
    assert!(error.contains("bob@test.ellkan") && error.contains("Bob@Test.Ellkan"), "{error}");
}
