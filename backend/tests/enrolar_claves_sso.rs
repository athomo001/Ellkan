// Autor: Athan Espinoza

//! Pendiente #133: una cuenta creada por SSO (JIT) nace sin claves y las
//! sube una sola vez en su primer acceso; `GET /me` avisa que falta, y
//! `GET /auth/setup-status` dice si hay un proveedor configurado.

mod common;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Value, json};

fn claves(n: u8) -> Value {
    json!({
        "public_key_x25519_b64": B64.encode([n; 32]),
        "public_key_ed25519_b64": B64.encode([n + 1; 32]),
        "encrypted_private_key_blob_b64": B64.encode([n + 2; 80]),
        "private_key_nonce_b64": B64.encode([n + 3; 24]),
        "kdf_salt_b64": B64.encode([n + 4; 16]),
        "kdf_params": ellkan_crypto::derivacion::ParametrosKdf::ACTUAL,
        "auth_key_b64": B64.encode([7u8; 32]),
    })
}

#[tokio::test]
async fn una_cuenta_sin_claves_las_enrola_una_sola_vez() {
    let entorno = common::levantar().await;
    let ana = common::registrar(&entorno, "ana@test.ellkan").await;
    let sesion = common::login(&entorno, &ana).await;

    let perfil = |entorno: &common::Entorno| {
        let pedido = entorno.cliente.get(format!("{}/me", entorno.base)).bearer_auth(sesion).send();
        async move { pedido.await.unwrap().json::<Value>().await.unwrap() }
    };
    assert_eq!(perfil(&entorno).await["needs_key_enrollment"], false);

    // Una cuenta con claves no puede reemplazarlas por esta vía.
    let resp = entorno
        .cliente
        .post(format!("{}/me/keys/enroll", entorno.base))
        .bearer_auth(sesion)
        .json(&claves(10))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);

    // Como la deja el alta JIT de SSO: blob vacío y públicas en cero.
    sqlx::query(
        "update user_keys set encrypted_private_key_blob = '', public_key_x25519 = $2, public_key_ed25519 = $2
         where user_id = $1",
    )
    .bind(ana.user_id)
    .bind(vec![0u8; 32])
    .execute(&entorno.pool)
    .await
    .unwrap();
    assert_eq!(perfil(&entorno).await["needs_key_enrollment"], true);

    // Largos equivocados: 400, y no se guarda nada.
    let mut mal = claves(20);
    mal["private_key_nonce_b64"] = json!(B64.encode([1u8; 12]));
    let resp = entorno
        .cliente
        .post(format!("{}/me/keys/enroll", entorno.base))
        .bearer_auth(sesion)
        .json(&mal)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    let resp = entorno
        .cliente
        .post(format!("{}/me/keys/enroll", entorno.base))
        .bearer_auth(sesion)
        .json(&claves(20))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    assert_eq!(perfil(&entorno).await["needs_key_enrollment"], false);
    let (publica,): (Vec<u8>,) = sqlx::query_as("select public_key_x25519 from user_keys where user_id = $1")
        .bind(ana.user_id)
        .fetch_one(&entorno.pool)
        .await
        .unwrap();
    assert_eq!(publica, vec![20u8; 32]);

    // Una segunda vez ya no: no pisa las claves recién creadas.
    let resp = entorno
        .cliente
        .post(format!("{}/me/keys/enroll", entorno.base))
        .bearer_auth(sesion)
        .json(&claves(30))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);

    // La auditoría la escribe el consumidor de eventos, en segundo plano.
    let mut eventos = 0;
    for _ in 0..50 {
        (eventos,) =
            sqlx::query_as("select count(*) from audit_log_entries where event_type = 'user.keys_enrolled' and actor_user_id = $1")
                .bind(ana.user_id)
                .fetch_one(&entorno.pool)
                .await
                .unwrap();
        if eventos > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(eventos, 1i64);
}

#[tokio::test]
async fn setup_status_dice_si_hay_sso() {
    let entorno = common::levantar().await;
    let estado: Value = entorno
        .cliente
        .get(format!("{}/auth/setup-status", entorno.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(estado["sso_enabled"], false);
}
