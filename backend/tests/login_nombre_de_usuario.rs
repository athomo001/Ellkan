// Autor: Athan Espinoza

//! F-47 C (#49): entrar con el correo o con un nombre de usuario sin filtrar
//! el correo ni si la cuenta existe; re-sellado del blob con el `user_id`
//! como AAD con la misma passphrase (`POST /me/key-rewrap`).

mod common;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::Signer;
use ellkan_crypto::clave_privada;
use ellkan_crypto::derivacion::ParametrosKdf;
use secrecy::ExposeSecret;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

async fn fijar_usuario(entorno: &common::Entorno, sesion: Uuid, username: Value) -> reqwest::Response {
    entorno
        .cliente
        .put(format!("{}/me/username", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({ "username": username }))
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn se_entra_por_nombre_de_usuario_sin_revelar_el_correo() {
    let entorno = common::levantar().await;
    let ana = common::registrar(&entorno, "Ana.Perez@test.ellkan").await;
    let sesion = common::login(&entorno, &ana).await;

    // Validación y unicidad.
    assert_eq!(fijar_usuario(&entorno, sesion, json!("a@b")).await.status(), 400);
    assert_eq!(fijar_usuario(&entorno, sesion, json!("x")).await.status(), 400);
    let r = fijar_usuario(&entorno, sesion, json!("  AnaP ")).await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.json::<Value>().await.unwrap()["username"], "anap", "se guarda en minúsculas");
    let beto = common::registrar(&entorno, "beto@test.ellkan").await;
    let s_beto = common::login(&entorno, &beto).await;
    assert_eq!(fijar_usuario(&entorno, s_beto, json!("anap")).await.status(), 400, "ya en uso");

    // prelogin por nombre: da el user_id real, nunca el correo.
    let pre = common::prelogin(&entorno, "AnaP").await;
    assert_eq!(pre["user_id"], ana.user_id.to_string());
    assert_eq!(pre["email"], "anap", "no se revela el correo a quien entra por nombre");
    // Por correo, como antes (el guardado).
    let pre_correo = common::prelogin(&entorno, "ana.perez@test.ellkan").await;
    assert_eq!(pre_correo["email"], "Ana.Perez@test.ellkan");
    assert_eq!(pre_correo["kdf_salt_b64"], pre["kdf_salt_b64"]);

    // Un nombre sin cuenta: id falso estable, con forma de UUIDv7.
    let falso_1 = common::prelogin(&entorno, "fantasma").await;
    let falso_2 = common::prelogin(&entorno, "FANTASMA").await;
    assert_eq!(falso_1["user_id"], falso_2["user_id"]);
    let id_falso: Uuid = falso_1["user_id"].as_str().unwrap().parse().unwrap();
    assert_eq!(id_falso.get_version_num(), 7);
    assert_ne!(id_falso, ana.user_id);

    // key-material por nombre, con la auth_key: tampoco devuelve el correo.
    let resp = common::key_material_con_passphrase(&entorno, "anap", &ana.passphrase).await;
    assert_eq!(resp.status(), 200);
    let material: Value = resp.json().await.unwrap();
    assert_eq!(material["email"], "anap");
    assert_eq!(material["user_id"], ana.user_id.to_string());

    // challenge + verify por nombre (dispositivo ya conocido).
    let resp = entorno
        .cliente
        .post(format!("{}/auth/challenge", entorno.base))
        .json(&json!({ "email": "anap" }))
        .send()
        .await
        .unwrap();
    let nonce = B64.decode(resp.json::<Value>().await.unwrap()["nonce_b64"].as_str().unwrap()).unwrap();
    let firma = ana.ed25519.firmante().sign(&nonce);
    let resp = entorno
        .cliente
        .post(format!("{}/auth/verify", entorno.base))
        .json(&json!({
            "identifier": "anap",
            "nonce_b64": B64.encode(&nonce),
            "signature_b64": B64.encode(firma.to_bytes()),
            "device_token_hash_b64": B64.encode(Sha256::digest(ana.device_token)),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.json::<Value>().await.unwrap()["estado"], "completo");

    // Quitarlo: deja de servir.
    assert_eq!(fijar_usuario(&entorno, sesion, Value::Null).await.status(), 200);
    assert_eq!(
        common::prelogin(&entorno, "anap").await["user_id"]
            .as_str()
            .unwrap()
            .parse::<Uuid>()
            .unwrap()
            .get_version_num(),
        7
    );
    assert_ne!(common::prelogin(&entorno, "anap").await["user_id"], ana.user_id.to_string());
}

/// Cuerpo de `key-rewrap`: las privadas re-selladas con `aad` y la sal dada.
async fn cuerpo_resellado(entorno: &common::Entorno, u: &common::Usuario, salt: [u8; 16], aad: &[u8]) -> Value {
    let mut privadas = [0u8; 64];
    privadas[..32].copy_from_slice(u.x25519.privada().to_bytes().as_slice());
    privadas[32..].copy_from_slice(&u.ed25519.firmante().to_bytes());
    let sellada = clave_privada::cifrar_clave_privada(&u.passphrase, salt, ParametrosKdf::ACTUAL, &privadas, aad).unwrap();
    let (challenge, firma) = common::prueba_de_posesion(entorno, &u.email, &privadas[32..], &sellada).await;
    json!({
        "encrypted_private_key_blob_b64": B64.encode(&sellada.blob.envoltura.ciphertext),
        "private_key_nonce_b64": B64.encode(sellada.blob.envoltura.nonce),
        "kdf_salt_b64": B64.encode(sellada.blob.salt),
        "kdf_params": ParametrosKdf::ACTUAL,
        "auth_key_b64": B64.encode(sellada.auth_key.expose_secret()),
        "challenge_nonce_b64": challenge,
        "signature_b64": firma,
    })
}

#[tokio::test]
async fn key_rewrap_cambia_el_aad_sin_cambiar_la_passphrase_ni_cerrar_sesiones() {
    let entorno = common::levantar().await;
    let u = common::registrar(&entorno, "rewrap@test.ellkan").await;
    let sesion = common::login(&entorno, &u).await;
    let pre = common::prelogin(&entorno, &u.email).await;
    let salt: [u8; 16] = B64.decode(pre["kdf_salt_b64"].as_str().unwrap()).unwrap().try_into().unwrap();
    let aad = clave_privada::aad_de_usuario(&u.user_id.to_string());

    // Otra sal = otra passphrase (u otra derivación): no.
    let otra = cuerpo_resellado(&entorno, &u, [9u8; 16], &aad).await;
    let resp = entorno
        .cliente
        .post(format!("{}/me/key-rewrap", entorno.base))
        .bearer_auth(sesion)
        .json(&otra)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);

    let cuerpo = cuerpo_resellado(&entorno, &u, salt, &aad).await;
    let resp = entorno
        .cliente
        .post(format!("{}/me/key-rewrap", entorno.base))
        .bearer_auth(sesion)
        .json(&cuerpo)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // La sesión sigue; el blob guardado abre con el AAD nuevo y la misma passphrase.
    let resp = entorno.cliente.get(format!("{}/me", entorno.base)).bearer_auth(sesion).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let resp = common::key_material_con_passphrase(&entorno, &u.email, &u.passphrase).await;
    assert_eq!(resp.status(), 200, "el verificador no cambió");
    let m: Value = resp.json().await.unwrap();
    let blob = clave_privada::EncryptedPrivateKeyBlob {
        salt,
        parametros: ParametrosKdf::ACTUAL,
        envoltura: ellkan_crypto::aead::Envoltura {
            nonce: B64.decode(m["private_key_nonce_b64"].as_str().unwrap()).unwrap().try_into().unwrap(),
            ciphertext: B64.decode(m["encrypted_private_key_blob_b64"].as_str().unwrap()).unwrap(),
        },
    };
    assert!(clave_privada::descifrar_clave_privada(&u.passphrase, &blob, &aad).is_ok());
    assert!(clave_privada::descifrar_clave_privada(&u.passphrase, &blob, u.email.as_bytes()).is_err());
    assert!(clave_privada::descifrar_clave_privada_con_aads(&u.passphrase, &blob, &[&aad, u.email.as_bytes()]).is_ok());
}
