// Autor: Athan Espinoza

//! Perfil propio (F-01) — `GET /me`, avatar (`/me/avatar`) y cambio de
//! passphrase (`POST /me/change-passphrase`).

mod common;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ellkan_crypto::aead::Envoltura;
use ellkan_crypto::clave_privada::{self, EncryptedPrivateKeyBlob};
use ellkan_crypto::secretos::PassphraseSecreta;
use secrecy::ExposeSecret;
use secrecy::SecretBox;
use serde_json::{Value, json};

const PNG_1PX: &[u8] = &[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52];

#[tokio::test]
async fn get_me_devuelve_el_perfil_real() {
    let entorno = common::levantar().await;
    let user = common::registrar(&entorno, "perfil@test.ellkan").await;
    let sesion = common::login(&entorno, &user).await;

    let resp = entorno.cliente.get(format!("{}/me", entorno.base)).bearer_auth(sesion).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["email"], user.email);
    assert_eq!(cuerpo["role"], "user");
    assert!(cuerpo["created_at"].is_string());
    assert!(cuerpo["keys_created_at"].is_string());
}

#[tokio::test]
async fn avatar_se_sube_se_lee_y_se_borra() {
    let entorno = common::levantar().await;
    let user = common::registrar(&entorno, "avatar@test.ellkan").await;
    let sesion = common::login(&entorno, &user).await;

    // Sin avatar todavía -> 404, no un 200 con body vacío.
    let resp = entorno.cliente.get(format!("{}/me/avatar", entorno.base)).bearer_auth(sesion).send().await.unwrap();
    assert_eq!(resp.status(), 404);

    let resp = entorno
        .cliente
        .put(format!("{}/me/avatar", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({ "avatar_b64": B64.encode(PNG_1PX), "content_type": "image/png" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = entorno.cliente.get(format!("{}/me/avatar", entorno.base)).bearer_auth(sesion).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("content-type").unwrap(), "image/png");
    assert_eq!(resp.bytes().await.unwrap().as_ref(), PNG_1PX);

    let resp = entorno
        .cliente
        .delete(format!("{}/me/avatar", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let resp = entorno.cliente.get(format!("{}/me/avatar", entorno.base)).bearer_auth(sesion).send().await.unwrap();
    assert_eq!(resp.status(), 404, "borrar el avatar debe volver a dar 404, no un 200 con contenido viejo");
}

#[tokio::test]
async fn avatar_rechaza_content_type_no_permitido_y_tamano_excesivo() {
    let entorno = common::levantar().await;
    let user = common::registrar(&entorno, "avatar-invalido@test.ellkan").await;
    let sesion = common::login(&entorno, &user).await;

    let resp = entorno
        .cliente
        .put(format!("{}/me/avatar", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({ "avatar_b64": B64.encode(PNG_1PX), "content_type": "image/svg+xml" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "un content_type fuera del allowlist debe rechazarse");

    // Apenas por encima del límite de la app (2 MB decodificados) pero bien
    // por debajo del límite de body de la ruta (3 MB, ver `lib.rs`) — así el
    // rechazo lo hace la validación de `me/service.rs` (400 limpio), no el
    // límite de Axum (413, forma de respuesta distinta, no es lo que este
    // test verifica).
    let demasiado_grande = vec![0u8; 2 * 1024 * 1024 + 1024];
    let resp = entorno
        .cliente
        .put(format!("{}/me/avatar", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({ "avatar_b64": B64.encode(&demasiado_grande), "content_type": "image/png" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "un avatar de más de 2MB debe rechazarse");
}

#[tokio::test]
async fn cambiar_passphrase_rota_la_clave_e_invalida_la_sesion_vieja_incluida_la_actual() {
    let entorno = common::levantar().await;
    let user = common::registrar(&entorno, "cambio-passphrase@test.ellkan").await;
    let sesion_vieja = common::login(&entorno, &user).await;

    // La sesión funciona antes de cambiar la passphrase.
    let resp = entorno.cliente.get(format!("{}/me", entorno.base)).bearer_auth(sesion_vieja).send().await.unwrap();
    assert_eq!(resp.status(), 200);

    // Mismo flujo que haría el cliente real: abrir el blob viejo con la
    // passphrase actual, volver a sellarlo con una nueva.
    let mut privadas = [0u8; 64];
    privadas[..32].copy_from_slice(user.x25519.privada().to_bytes().as_slice());
    privadas[32..].copy_from_slice(&user.ed25519.firmante().to_bytes());
    let nueva_passphrase: PassphraseSecreta = SecretBox::new(Box::new("una-passphrase-nueva-bien-larga".to_string()));
    let nueva_salt: [u8; 16] = ellkan_crypto::aleatoriedad::bytes_aleatorios();
    let nuevo_blob_sellado = clave_privada::cifrar_clave_privada(
        &nueva_passphrase,
        nueva_salt,
        ellkan_crypto::derivacion::ParametrosKdf::ACTUAL,
        &privadas,
        user.email.as_bytes(),
    )
    .unwrap();
    let nuevo_blob = &nuevo_blob_sellado.blob;
    let (challenge, firma) = common::prueba_de_posesion(&entorno, &user.email, &privadas[32..], &nuevo_blob_sellado).await;

    let resp = entorno
        .cliente
        .post(format!("{}/me/change-passphrase", entorno.base))
        .bearer_auth(sesion_vieja)
        .json(&json!({
            "encrypted_private_key_blob_b64": B64.encode(&nuevo_blob.envoltura.ciphertext),
            "private_key_nonce_b64": B64.encode(nuevo_blob.envoltura.nonce),
            "kdf_salt_b64": B64.encode(nuevo_blob.salt),
            "kdf_params": ellkan_crypto::derivacion::ParametrosKdf::ACTUAL,
            "auth_key_b64": B64.encode(nuevo_blob_sellado.auth_key.expose_secret()),
            "challenge_nonce_b64": challenge,
            "signature_b64": firma,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // La sesión vieja (la misma que hizo el cambio) queda invalidada de
    // inmediato — mismo criterio que desactivar un usuario.
    let resp = entorno.cliente.get(format!("{}/me", entorno.base)).bearer_auth(sesion_vieja).send().await.unwrap();
    assert_eq!(resp.status(), 401, "la sesión que cambió la passphrase también queda invalidada");

    // El blob nuevo quedó persistido de verdad en `user_keys`.
    let fila: (Vec<u8>, Vec<u8>, Vec<u8>) =
        sqlx::query_as("select encrypted_private_key_blob, private_key_nonce, kdf_salt from user_keys where user_id = $1")
            .bind(user.user_id)
            .fetch_one(&entorno.pool)
            .await
            .unwrap();
    assert_eq!(fila.0, nuevo_blob.envoltura.ciphertext);

    // La passphrase vieja ya no abre el blob nuevo.
    let salt: [u8; 16] = fila.2.clone().try_into().unwrap();
    let nonce: [u8; 24] = fila.1.clone().try_into().unwrap();
    let blob_nuevo_leido = Envoltura { nonce, ciphertext: fila.0.clone() };
    let blob_para_abrir = EncryptedPrivateKeyBlob {
        salt,
        parametros: ellkan_crypto::derivacion::ParametrosKdf::ACTUAL,
        envoltura: blob_nuevo_leido,
    };
    assert!(
        clave_privada::descifrar_clave_privada(&user.passphrase, &blob_para_abrir, user.email.as_bytes()).is_err(),
        "la passphrase vieja no debería poder abrir el blob ya rotado"
    );

    // La passphrase nueva sí lo abre y recupera exactamente el mismo material.
    let abierto = clave_privada::descifrar_clave_privada(&nueva_passphrase, &blob_para_abrir, user.email.as_bytes()).unwrap();
    assert_eq!(abierto.as_slice(), privadas.as_slice());
}

#[tokio::test]
async fn cambiar_passphrase_rechaza_longitudes_invalidas() {
    let entorno = common::levantar().await;
    let user = common::registrar(&entorno, "passphrase-invalida@test.ellkan").await;
    let sesion = common::login(&entorno, &user).await;

    let resp = entorno
        .cliente
        .post(format!("{}/me/change-passphrase", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({
            "encrypted_private_key_blob_b64": B64.encode(b"muy corto"),
            "private_key_nonce_b64": B64.encode(b"nonce-de-longitud-incorrecta"),
            "kdf_salt_b64": B64.encode(b"salt-mal"),
            "kdf_params": ellkan_crypto::derivacion::ParametrosKdf::ACTUAL,
            "auth_key_b64": B64.encode([7u8; 32]),
            "challenge_nonce_b64": B64.encode([0u8; 32]),
            "signature_b64": B64.encode([0u8; 64]),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

/// QA-06: una sesión completa (robada, por ejemplo) no alcanza para
/// reemplazar la clave privada sellada: sin una firma de la identidad sobre
/// ESE blob, el servidor responde 403 y `user_keys` no cambia. Tampoco sirve
/// reusar un challenge ni la firma de otro blob.
#[tokio::test]
async fn cambiar_passphrase_exige_prueba_de_posesion_de_la_identidad() {
    let entorno = common::levantar().await;
    let user = common::registrar(&entorno, "posesion-qa06@test.ellkan").await;
    let sesion = common::login(&entorno, &user).await;
    let blob_original: (Vec<u8>,) = sqlx::query_as("select encrypted_private_key_blob from user_keys where user_id = $1")
        .bind(user.user_id)
        .fetch_one(&entorno.pool)
        .await
        .unwrap();

    let basura_sellado = clave_privada::cifrar_clave_privada(
        &SecretBox::new(Box::new("passphrase-del-atacante-larga".to_string())),
        [9u8; 16],
        ellkan_crypto::derivacion::ParametrosKdf::ACTUAL,
        &[0u8; 64],
        user.email.as_bytes(),
    )
    .unwrap();
    let basura = &basura_sellado.blob;
    let cuerpo = |challenge: &str, firma: &str| {
        json!({
            "encrypted_private_key_blob_b64": B64.encode(&basura.envoltura.ciphertext),
            "private_key_nonce_b64": B64.encode(basura.envoltura.nonce),
            "kdf_salt_b64": B64.encode(basura.salt),
            "kdf_params": ellkan_crypto::derivacion::ParametrosKdf::ACTUAL,
            "auth_key_b64": B64.encode(basura_sellado.auth_key.expose_secret()),
            "challenge_nonce_b64": challenge,
            "signature_b64": firma,
        })
    };
    let enviar = |body: Value| {
        entorno
            .cliente
            .post(format!("{}/me/change-passphrase", entorno.base))
            .bearer_auth(sesion)
            .json(&body)
            .send()
    };

    // Firma con una clave que no es la de la cuenta: 403, y el challenge
    // queda consumido igual.
    let (challenge, firma_ajena) = common::prueba_de_posesion(&entorno, &user.email, &[5u8; 32], &basura_sellado).await;
    assert_eq!(enviar(cuerpo(&challenge, &firma_ajena)).await.unwrap().status(), 403);

    // Firma legítima, pero sobre ese challenge ya consumido.
    let privada = user.ed25519.firmante().to_bytes();
    let firma_reusada = B64.encode(clave_privada::firmar_reemplazo_clave_privada(
        &privada,
        &B64.decode(&challenge).unwrap(),
        &clave_privada::Reemplazo {
            blob: &basura.envoltura.ciphertext,
            nonce: &basura.envoltura.nonce,
            salt: &basura.salt,
            parametros: &basura.parametros,
            auth_key: basura_sellado.auth_key.expose_secret(),
        },
    ));
    assert_eq!(
        enviar(cuerpo(&challenge, &firma_reusada)).await.unwrap().status(),
        403,
        "un challenge ya usado no sirve dos veces"
    );

    // Firma legítima de OTRO blob, presentada con el blob basura.
    let otro_sellado = clave_privada::cifrar_clave_privada(
        &user.passphrase,
        [3u8; 16],
        ellkan_crypto::derivacion::ParametrosKdf::ACTUAL,
        &[1u8; 64],
        user.email.as_bytes(),
    )
    .unwrap();
    let (challenge, firma_otro) = common::prueba_de_posesion(&entorno, &user.email, &privada, &otro_sellado).await;
    assert_eq!(enviar(cuerpo(&challenge, &firma_otro)).await.unwrap().status(), 403);

    let blob_intermedio: (Vec<u8>,) = sqlx::query_as("select encrypted_private_key_blob from user_keys where user_id = $1")
        .bind(user.user_id)
        .fetch_one(&entorno.pool)
        .await
        .unwrap();
    assert_eq!(blob_intermedio.0, blob_original.0, "ningún intento sin prueba válida escribió");

    // Con la prueba válida sí se acepta.
    let (challenge, firma) = common::prueba_de_posesion(&entorno, &user.email, &privada, &basura_sellado).await;
    assert_eq!(enviar(cuerpo(&challenge, &firma)).await.unwrap().status(), 200, "la prueba válida se acepta");

    let blob_final: (Vec<u8>,) = sqlx::query_as("select encrypted_private_key_blob from user_keys where user_id = $1")
        .bind(user.user_id)
        .fetch_one(&entorno.pool)
        .await
        .unwrap();
    assert_eq!(blob_final.0, basura.envoltura.ciphertext);
}
