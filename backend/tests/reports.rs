// Autor: Athan Espinoza

//! F-23: reportes operativos — `reportId` como enum cerrado (404 fuera de
//! él), y que cada reporte devuelva exactamente lo esperado contra datos
//! reales, nunca contenido cifrado.

mod common;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ellkan_crypto::aead;
use ellkan_crypto::sellado;
use secrecy::SecretBox;
use serde_json::{json, Value};
use uuid::Uuid;

#[tokio::test]
async fn reporte_invalido_da_404() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "reports-404@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion = common::login(&entorno, &admin).await;

    let resp = entorno
        .cliente
        .get(format!("{}/admin/reports/no_existe", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "un reportId fuera del enum cerrado debe ser 404, nunca un reporte vacío");
}

#[tokio::test]
async fn sin_admin_no_puede_leer_reportes() {
    let entorno = common::levantar().await;
    let user = common::registrar(&entorno, "reports-sin-admin@test.ellkan").await;
    let sesion = common::login(&entorno, &user).await;

    let resp = entorno
        .cliente
        .get(format!("{}/admin/reports/mfa_coverage", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn passwords_expired_respeta_el_umbral_de_la_politica() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "reports-pw-admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    // Umbral de 1 día — cualquier cuenta con `user_keys.created_at` de más
    // de 1 día atrás cuenta como "expirada" (sin F-15/rotación real, ver
    // nota del modelo).
    let resp = entorno
        .cliente
        .put(format!("{}/admin/password-policy", entorno.base))
        .bearer_auth(sesion_admin)
        .json(&json!({
            "min_passphrase_length": 12, "min_passphrase_entropy_bits": 60,
            "passphrase_rotation_days": 1, "generator_default_length": 20,
            "generator_charset_rules": {}, "max_clipboard_clear_minutes": null, "max_auto_lock_minutes": null,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let vieja = common::registrar(&entorno, "reports-pw-vieja@test.ellkan").await;
    let fresca = common::registrar(&entorno, "reports-pw-fresca@test.ellkan").await;
    sqlx::query("update user_keys set created_at = now() - interval '10 days' where user_id = $1")
        .bind(vieja.user_id)
        .execute(&entorno.pool)
        .await
        .unwrap();

    let resp = entorno
        .cliente
        .get(format!("{}/admin/reports/passwords_expired", entorno.base))
        .bearer_auth(sesion_admin)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["report_id"], "passwords_expired");
    let emails: Vec<String> =
        cuerpo["items"].as_array().unwrap().iter().map(|i| i["email"].as_str().unwrap().to_string()).collect();
    assert!(emails.contains(&vieja.email), "la cuenta vieja debe aparecer como expirada");
    assert!(!emails.contains(&fresca.email), "la cuenta recién creada no debe aparecer");
}

#[tokio::test]
async fn mfa_coverage_distingue_usuarios_con_y_sin_totp_confirmado() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "reports-mfa-admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    let con_mfa = common::registrar(&entorno, "reports-mfa-con@test.ellkan").await;
    let sin_mfa = common::registrar(&entorno, "reports-mfa-sin@test.ellkan").await;

    sqlx::query(
        "insert into user_totp_credentials (user_id, secret_ciphertext, secret_nonce, confirmed_at)
         values ($1, 'x', 'y', now())",
    )
    .bind(con_mfa.user_id)
    .execute(&entorno.pool)
    .await
    .unwrap();

    let resp = entorno
        .cliente
        .get(format!("{}/admin/reports/mfa_coverage", entorno.base))
        .bearer_auth(sesion_admin)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cuerpo: Value = resp.json().await.unwrap();
    let items = cuerpo["items"].as_array().unwrap();
    let fila_con = items.iter().find(|i| i["email"] == con_mfa.email).unwrap();
    let fila_sin = items.iter().find(|i| i["email"] == sin_mfa.email).unwrap();
    assert_eq!(fila_con["mfa_enabled"], true);
    assert_eq!(fila_sin["mfa_enabled"], false);
}

#[tokio::test]
async fn inactive_users_incluye_a_quien_nunca_inicio_sesion() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "reports-inactive-admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    let nunca_logueado = common::registrar(&entorno, "reports-inactive-nunca@test.ellkan").await;
    let activo = common::registrar(&entorno, "reports-inactive-activo@test.ellkan").await;
    common::login(&entorno, &activo).await;

    let resp = entorno
        .cliente
        .get(format!("{}/admin/reports/inactive_users", entorno.base))
        .bearer_auth(sesion_admin)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cuerpo: Value = resp.json().await.unwrap();
    let emails: Vec<String> =
        cuerpo["items"].as_array().unwrap().iter().map(|i| i["email"].as_str().unwrap().to_string()).collect();
    assert!(emails.contains(&nunca_logueado.email));
    assert!(!emails.contains(&activo.email), "un login reciente no debería contar como inactivo");
}

#[tokio::test]
async fn resources_never_rotated_excluye_lo_ya_editado() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "reports-res-admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    let owner = common::registrar(&entorno, "reports-res-owner@test.ellkan").await;
    let sesion_owner = common::login(&entorno, &owner).await;

    let dek_bytes: [u8; 32] = ellkan_crypto::aleatoriedad::bytes_aleatorios();
    let dek = SecretBox::new(Box::new(dek_bytes));
    let resource_id = Uuid::now_v7();
    let mut aad = Vec::new();
    aad.extend_from_slice(resource_id.as_bytes());
    aad.extend_from_slice(owner.user_id.as_bytes());
    let metadata_env = aead::cifrar(&dek, b"{}", &aad).unwrap();
    let secreto_env = aead::cifrar(&dek, b"secreto", &aad).unwrap();
    let sealed_dek = sellado::sellar_dek(owner.x25519.publica(), &dek);

    let resp_crear = entorno
        .cliente
        .post(format!("{}/resources", entorno.base))
        .bearer_auth(sesion_owner)
        .json(&json!({
            "id": resource_id, "resource_type_slug": "login-password",
            "metadata_ciphertext_b64": B64.encode(&metadata_env.ciphertext),
            "metadata_nonce_b64": B64.encode(metadata_env.nonce),
            "sealed_dek_b64": B64.encode(&sealed_dek),
            "secret_ciphertext_b64": B64.encode(&secreto_env.ciphertext),
            "secret_nonce_b64": B64.encode(secreto_env.nonce),
        }))
        .send()
        .await
        .unwrap();
    let status_crear = resp_crear.status();
    let texto_crear = resp_crear.text().await.unwrap();
    assert_eq!(status_crear, 200, "crear recurso debería devolver 200, body: {texto_crear}");

    // El umbral real (`?days=`) tiene un piso de 1 día (`service.rs`, evita
    // un umbral 0/negativo sin sentido) — se retrasa `created_at`/`updated_at`
    // 10 días a mano para simular un recurso genuinamente viejo sin tener
    // que esperar de verdad.
    sqlx::query("update resources set created_at = now() - interval '10 days', updated_at = now() - interval '10 days' where id = $1")
        .bind(resource_id)
        .execute(&entorno.pool)
        .await
        .unwrap();

    let resp = entorno
        .cliente
        .get(format!("{}/admin/reports/resources_never_rotated?days=1", entorno.base))
        .bearer_auth(sesion_admin)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cuerpo: Value = resp.json().await.unwrap();
    let ids: Vec<String> =
        cuerpo["items"].as_array().unwrap().iter().map(|i| i["resource_id"].as_str().unwrap().to_string()).collect();
    assert!(ids.contains(&resource_id.to_string()), "un recurso nunca editado debe aparecer");

    // Se edita -> `updated_at` avanza -> desaparece del reporte.
    let get = entorno
        .cliente
        .get(format!("{}/resources/{}", entorno.base, resource_id))
        .bearer_auth(sesion_owner)
        .send()
        .await
        .unwrap();
    let recurso: Value = get.json().await.unwrap();
    let sealed_dek_owner = sellado::sellar_dek(owner.x25519.publica(), &dek);
    let metadata_env2 = aead::cifrar(&dek, b"{}", &aad).unwrap();
    let secreto_env2 = aead::cifrar(&dek, b"secreto-nuevo", &aad).unwrap();
    entorno
        .cliente
        .put(format!("{}/resources/{}", entorno.base, resource_id))
        .bearer_auth(sesion_owner)
        .header("If-Match", recurso["updated_at"].as_str().unwrap())
        .json(&json!({
            "metadata_ciphertext_b64": B64.encode(&metadata_env2.ciphertext),
            "metadata_nonce_b64": B64.encode(metadata_env2.nonce),
            "envelopes": [{
                "recipient_user_id": owner.user_id,
                "sealed_dek_b64": B64.encode(&sealed_dek_owner),
                "secret_ciphertext_b64": B64.encode(&secreto_env2.ciphertext),
                "secret_nonce_b64": B64.encode(secreto_env2.nonce),
            }]
        }))
        .send()
        .await
        .unwrap();

    let resp = entorno
        .cliente
        .get(format!("{}/admin/reports/resources_never_rotated?days=1", entorno.base))
        .bearer_auth(sesion_admin)
        .send()
        .await
        .unwrap();
    let cuerpo: Value = resp.json().await.unwrap();
    let ids: Vec<String> =
        cuerpo["items"].as_array().unwrap().iter().map(|i| i["resource_id"].as_str().unwrap().to_string()).collect();
    assert!(!ids.contains(&resource_id.to_string()), "un recurso ya editado no debe aparecer más");
}
