// Autor: Athan Espinoza

//! ELK-01 (pentest 2026-11-26): una cuenta creada por SSO-JIT/SCIM/LDAP queda
//! con la clave Ed25519 de relleno `[0;32]` (punto de orden 4) hasta que
//! enrola sus claves. Con la verificación laxa (`verify`) se podía forjar una
//! firma (`R` de orden pequeño, `s = 0`) y entrar sin clave privada. El login
//! tiene que rechazarla.

mod common;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// Los 4 puntos del subgrupo de orden 4 que genera `A = [0;32]`, codificados:
/// identidad, `A`, `[2]A` y `-A`.
fn erres_de_orden_pequeno() -> [[u8; 32]; 4] {
    let mut identidad = [0u8; 32];
    identidad[0] = 0x01;
    let mut dos = [0xFFu8; 32];
    dos[0] = 0xEC;
    dos[31] = 0x7F;
    let mut menos_a = [0u8; 32];
    menos_a[31] = 0x80;
    [identidad, [0u8; 32], dos, menos_a]
}

#[tokio::test]
async fn el_login_rechaza_una_firma_forjada_contra_la_clave_de_relleno() {
    let entorno = common::levantar().await;
    let ana = common::registrar(&entorno, "ana-relleno@test.ellkan").await;

    // Como la dejaba el alta JIT de SSO antes de la migración 0068: blob vacío
    // y públicas en cero. Hoy la base lo impide (CHECK), así que se quitan los
    // CHECK en este contenedor de prueba para simular una fila heredada y
    // seguir probando la segunda barrera (`verify_strict`).
    sqlx::query(
        "alter table user_keys drop constraint user_keys_blob_no_vacio,
                               drop constraint user_keys_x25519_no_nula,
                               drop constraint user_keys_ed25519_no_nula",
    )
    .execute(&entorno.pool)
    .await
    .unwrap();
    sqlx::query(
        "update user_keys set encrypted_private_key_blob = '', public_key_x25519 = $2, public_key_ed25519 = $2
         where user_id = $1",
    )
    .bind(ana.user_id)
    .bind(vec![0u8; 32])
    .execute(&entorno.pool)
    .await
    .unwrap();

    let relleno = VerifyingKey::from_bytes(&[0u8; 32]).expect("[0;32] decodifica como punto de la curva");

    // Cada challenge se consume al verificar, así que se pide uno nuevo por
    // intento. Para casi cualquier nonce alguno de los 4 `R` pasa la
    // verificación laxa; si ninguno encaja, se pide otro.
    for _ in 0..10 {
        let resp = entorno
            .cliente
            .post(format!("{}/auth/challenge", entorno.base))
            .json(&json!({ "email": ana.email }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let cuerpo: Value = resp.json().await.unwrap();
        let nonce = B64.decode(cuerpo["nonce_b64"].as_str().unwrap()).unwrap();

        let forjada = erres_de_orden_pequeno().into_iter().find_map(|r| {
            let mut bytes = [0u8; 64];
            bytes[..32].copy_from_slice(&r);
            let firma = Signature::from_bytes(&bytes);
            relleno.verify(&nonce, &firma).is_ok().then_some(bytes)
        });
        let Some(firma) = forjada else { continue };

        // La firma engaña a la verificación laxa, que es la que usaba el login.
        assert!(relleno.verify(&nonce, &Signature::from_bytes(&firma)).is_ok());

        let resp = entorno
            .cliente
            .post(format!("{}/auth/verify", entorno.base))
            .json(&json!({
                "email": ana.email,
                "nonce_b64": B64.encode(&nonce),
                "signature_b64": B64.encode(firma),
                "device_token_hash_b64": B64.encode(Sha256::digest(ana.device_token)),
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 401, "el login no puede aceptar una firma forjada contra [0;32]");
        return;
    }
    panic!("ningún nonce admitió una forja en 10 intentos: revisar el test");
}
