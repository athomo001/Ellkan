// Autor: Athan Espinoza

//! F-36 (#134): con el acceso concedido, el contacto lee la bóveda del
//! titular (`GET /me/emergency-access/{id}/vault`) y la abre con las privadas
//! del titular. Antes de la aprobación: 403. Otra persona: 404. Cada lectura
//! queda en la auditoría. Con nivel `takeover`, el contacto le fija una
//! passphrase nueva al titular (`POST …/{id}/takeover`).

mod common;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ellkan_crypto::aead::{self, Envoltura};
use ellkan_crypto::clave_privada;
use ellkan_crypto::secretos::PassphraseSecreta;
use ellkan_crypto::sellado;
use secrecy::{ExposeSecret, SecretBox};
use serde_json::{Value, json};
use uuid::Uuid;

async fn crear_recurso(entorno: &common::Entorno, sesion: Uuid, owner: &common::Usuario, secreto: &[u8]) -> Uuid {
    let dek = SecretBox::new(Box::new(ellkan_crypto::aleatoriedad::bytes_aleatorios::<32>()));
    let id = Uuid::now_v7();
    let mut aad = Vec::new();
    aad.extend_from_slice(id.as_bytes());
    aad.extend_from_slice(owner.user_id.as_bytes());
    let metadata = aead::cifrar(&dek, br#"{"name":"Banco"}"#, &aad).unwrap();
    let cifrado = aead::cifrar(&dek, secreto, &aad).unwrap();
    let resp = entorno
        .cliente
        .post(format!("{}/resources", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({
            "id": id,
            "resource_type_slug": "login-password",
            "metadata_ciphertext_b64": B64.encode(&metadata.ciphertext),
            "metadata_nonce_b64": B64.encode(metadata.nonce),
            "sealed_dek_b64": B64.encode(sellado::sellar_dek(owner.x25519.publica(), &dek)),
            "secret_ciphertext_b64": B64.encode(&cifrado.ciphertext),
            "secret_nonce_b64": B64.encode(cifrado.nonce),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    id
}

async fn boveda(entorno: &common::Entorno, sesion: Uuid, id: &str) -> reqwest::Response {
    entorno
        .cliente
        .get(format!("{}/me/emergency-access/{id}/vault", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap()
}

async fn post(entorno: &common::Entorno, sesion: Uuid, ruta: &str) -> u16 {
    entorno
        .cliente
        .post(format!("{}{ruta}", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

#[tokio::test]
async fn el_contacto_lee_la_boveda_del_titular_solo_con_el_acceso_concedido() {
    let entorno = common::levantar().await;
    let titular = common::registrar(&entorno, "titular@test.ellkan").await;
    let s_titular = common::login(&entorno, &titular).await;
    let contacto = common::registrar(&entorno, "contacto@test.ellkan").await;
    let s_contacto = common::login(&entorno, &contacto).await;
    let otro = common::registrar(&entorno, "otro@test.ellkan").await;
    let s_otro = common::login(&entorno, &otro).await;

    let propio = crear_recurso(&entorno, s_titular, &titular, b"clave-del-banco").await;
    // Un recurso de otra persona compartido con el titular no es del titular:
    // no tiene que aparecer.
    let ajeno = crear_recurso(&entorno, s_otro, &otro, b"ajeno").await;
    sqlx::query(
        "insert into permissions (subject_type, subject_id, grantee_type, grantee_id, level) values ('resource', $1, 'user', $2, 'read')",
    )
    .bind(ajeno)
    .bind(titular.user_id)
    .execute(&entorno.pool)
    .await
    .unwrap();

    // Material: las privadas del titular selladas para el contacto (lo que
    // hace el cliente al designar).
    let material = sellado::sellar_bytes(contacto.x25519.publica(), titular.x25519.privada().to_bytes().as_slice());
    let resp = entorno
        .cliente
        .post(format!("{}/me/emergency-access", entorno.base))
        .bearer_auth(s_titular)
        .json(&json!({
            "grantee_id": contacto.user_id,
            "access_level": "view",
            "sealed_material_b64": B64.encode(&material),
            "wait_time_days": 7,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let id = resp.json::<Value>().await.unwrap()["id"].as_str().unwrap().to_string();

    assert_eq!(post(&entorno, s_contacto, &format!("/me/emergency-access/{id}/accept")).await, 200);
    assert_eq!(boveda(&entorno, s_contacto, &id).await.status(), 403, "aceptado pero sin solicitud concedida");
    assert_eq!(post(&entorno, s_contacto, &format!("/me/emergency-access/{id}/request")).await, 200);
    assert_eq!(boveda(&entorno, s_contacto, &id).await.status(), 403, "solicitud pendiente");
    assert_eq!(post(&entorno, s_titular, &format!("/me/emergency-access/{id}/approve")).await, 200);

    assert_eq!(boveda(&entorno, s_otro, &id).await.status(), 404, "un tercero no ve ni que existe");
    assert_eq!(boveda(&entorno, s_titular, &id).await.status(), 404, "el titular no es el contacto");

    let resp = boveda(&entorno, s_contacto, &id).await;
    assert_eq!(resp.status(), 200);
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["granter"]["email"], "titular@test.ellkan");
    let recursos = cuerpo["resources"].as_array().unwrap();
    assert_eq!(recursos.len(), 1, "sólo lo que es del titular: {recursos:?}");
    let r = &recursos[0];
    assert_eq!(r["id"], propio.to_string());

    // El contacto abre todo con lo que recibió.
    let privada_titular =
        sellado::abrir_bytes(contacto.x25519.privada(), &B64.decode(cuerpo["sealed_material_b64"].as_str().unwrap()).unwrap()).unwrap();
    let privada_titular: [u8; 32] = privada_titular[..32].try_into().unwrap();
    let privada_titular = x25519_dalek::StaticSecret::from(privada_titular);
    let dek = sellado::abrir_dek(&privada_titular, &B64.decode(r["sealed_dek_b64"].as_str().unwrap()).unwrap()).unwrap();
    let mut aad = Vec::new();
    aad.extend_from_slice(propio.as_bytes());
    aad.extend_from_slice(titular.user_id.as_bytes());
    let nonce: [u8; 24] = B64.decode(r["secret_nonce_b64"].as_str().unwrap()).unwrap().try_into().unwrap();
    let env = Envoltura {
        nonce,
        ciphertext: B64.decode(r["secret_ciphertext_b64"].as_str().unwrap()).unwrap(),
    };
    assert_eq!(aead::descifrar(&dek, &env, &aad).unwrap(), b"clave-del-banco");

    // Auditado (el escritor de auditoría es asíncrono).
    let mut auditado = 0i64;
    for _ in 0..50 {
        auditado = sqlx::query_scalar(
            "select count(*) from audit_log_entries where event_type = 'emergency_access.vault_viewed' and actor_user_id = $1",
        )
        .bind(contacto.user_id)
        .fetch_one(&entorno.pool)
        .await
        .unwrap();
        if auditado > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(auditado, 1);

    // Si el titular revoca, se acaba.
    let resp = entorno
        .cliente
        .delete(format!("{}/me/emergency-access/{id}", entorno.base))
        .bearer_auth(s_titular)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(boveda(&entorno, s_contacto, &id).await.status(), 404);
}

/// Titular designa a contacto con `nivel`, el contacto acepta y pide, el
/// titular aprueba. Devuelve el id de la relación.
async fn designar_y_conceder(
    entorno: &common::Entorno,
    titular: &common::Usuario,
    s_titular: Uuid,
    contacto: &common::Usuario,
    s_contacto: Uuid,
    nivel: &str,
) -> String {
    let mut privadas = [0u8; 64];
    privadas[..32].copy_from_slice(titular.x25519.privada().to_bytes().as_slice());
    privadas[32..].copy_from_slice(&titular.ed25519.firmante().to_bytes());
    let resp = entorno
        .cliente
        .post(format!("{}/me/emergency-access", entorno.base))
        .bearer_auth(s_titular)
        .json(&json!({
            "grantee_id": contacto.user_id,
            "access_level": nivel,
            "sealed_material_b64": B64.encode(sellado::sellar_bytes(contacto.x25519.publica(), &privadas)),
            "wait_time_days": 1,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let id = resp.json::<Value>().await.unwrap()["id"].as_str().unwrap().to_string();
    assert_eq!(post(entorno, s_contacto, &format!("/me/emergency-access/{id}/accept")).await, 200);
    assert_eq!(post(entorno, s_contacto, &format!("/me/emergency-access/{id}/request")).await, 200);
    assert_eq!(post(entorno, s_titular, &format!("/me/emergency-access/{id}/approve")).await, 200);
    id
}

/// Cuerpo de `takeover` (= el de `change-passphrase`) armado por el
/// contacto con las privadas del titular que abrió del material.
async fn cuerpo_takeover(entorno: &common::Entorno, titular: &common::Usuario, passphrase: &PassphraseSecreta) -> Value {
    let mut privadas = [0u8; 64];
    privadas[..32].copy_from_slice(titular.x25519.privada().to_bytes().as_slice());
    privadas[32..].copy_from_slice(&titular.ed25519.firmante().to_bytes());
    let sellada = clave_privada::cifrar_clave_privada(
        passphrase,
        ellkan_crypto::aleatoriedad::bytes_aleatorios(),
        ellkan_crypto::derivacion::ParametrosKdf::ACTUAL,
        &privadas,
        titular.email.as_bytes(),
    )
    .unwrap();
    let (challenge, firma) = common::prueba_de_posesion(entorno, &titular.email, &privadas[32..], &sellada).await;
    json!({
        "encrypted_private_key_blob_b64": B64.encode(&sellada.blob.envoltura.ciphertext),
        "private_key_nonce_b64": B64.encode(sellada.blob.envoltura.nonce),
        "kdf_salt_b64": B64.encode(sellada.blob.salt),
        "kdf_params": ellkan_crypto::derivacion::ParametrosKdf::ACTUAL,
        "auth_key_b64": B64.encode(sellada.auth_key.expose_secret()),
        "challenge_nonce_b64": challenge,
        "signature_b64": firma,
    })
}

#[tokio::test]
async fn takeover_fija_passphrase_nueva_al_titular_solo_con_ese_nivel() {
    let entorno = common::levantar().await;
    let titular = common::registrar(&entorno, "titular@test.ellkan").await;
    let s_titular = common::login(&entorno, &titular).await;
    let contacto = common::registrar(&entorno, "contacto@test.ellkan").await;
    let s_contacto = common::login(&entorno, &contacto).await;
    let nueva: PassphraseSecreta = SecretBox::new(Box::new("passphrase-que-fija-el-contacto".to_string()));

    // Con nivel `view` no hay takeover.
    let solo_ver = designar_y_conceder(&entorno, &titular, s_titular, &contacto, s_contacto, "view").await;
    let cuerpo = cuerpo_takeover(&entorno, &titular, &nueva).await;
    let resp = entorno
        .cliente
        .post(format!("{}/me/emergency-access/{solo_ver}/takeover", entorno.base))
        .bearer_auth(s_contacto)
        .json(&cuerpo)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
    let resp = entorno
        .cliente
        .delete(format!("{}/me/emergency-access/{solo_ver}", entorno.base))
        .bearer_auth(s_titular)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let id = designar_y_conceder(&entorno, &titular, s_titular, &contacto, s_contacto, "takeover").await;

    // Una firma que no es del titular no pasa.
    let mut falsa = cuerpo_takeover(&entorno, &titular, &nueva).await;
    falsa["signature_b64"] = json!(B64.encode([7u8; 64]));
    let resp = entorno
        .cliente
        .post(format!("{}/me/emergency-access/{id}/takeover", entorno.base))
        .bearer_auth(s_contacto)
        .json(&falsa)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    let cuerpo = cuerpo_takeover(&entorno, &titular, &nueva).await;
    let resp = entorno
        .cliente
        .post(format!("{}/me/emergency-access/{id}/takeover", entorno.base))
        .bearer_auth(s_contacto)
        .json(&cuerpo)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // Las sesiones del titular se cerraron; el blob nuevo abre con la passphrase nueva.
    let resp = entorno.cliente.get(format!("{}/me", entorno.base)).bearer_auth(s_titular).send().await.unwrap();
    assert_eq!(resp.status(), 401);
    let (blob, nonce, salt): (Vec<u8>, Vec<u8>, Vec<u8>) =
        sqlx::query_as("select encrypted_private_key_blob, private_key_nonce, kdf_salt from user_keys where user_id = $1")
            .bind(titular.user_id)
            .fetch_one(&entorno.pool)
            .await
            .unwrap();
    let guardado = clave_privada::EncryptedPrivateKeyBlob {
        salt: salt.try_into().unwrap(),
        parametros: ellkan_crypto::derivacion::ParametrosKdf::ACTUAL,
        envoltura: Envoltura { nonce: nonce.try_into().unwrap(), ciphertext: blob },
    };
    assert!(clave_privada::descifrar_clave_privada(&nueva, &guardado, titular.email.as_bytes()).is_ok());
    assert!(clave_privada::descifrar_clave_privada(&titular.passphrase, &guardado, titular.email.as_bytes()).is_err());

    let mut auditado = 0i64;
    for _ in 0..50 {
        auditado = sqlx::query_scalar("select count(*) from audit_log_entries where event_type = 'emergency_access.takeover'")
            .fetch_one(&entorno.pool)
            .await
            .unwrap();
        if auditado > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(auditado, 1);
}
