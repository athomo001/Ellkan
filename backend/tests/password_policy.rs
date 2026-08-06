// Autor: Athan Espinoza

//! F-15: sólo admin lee/cambia la política, el piso de `min_passphrase_length`
//! (12) se exige server-side aunque el resto de la validación de entropía
//! corra client-side, y los cambios persisten.

mod common;

use serde_json::json;

#[tokio::test]
async fn no_admin_no_puede_leer_ni_cambiar_la_politica() {
    let entorno = common::levantar().await;
    let user = common::registrar(&entorno, "sin-admin@test.ellkan").await;
    let sesion = common::login(&entorno, &user).await;

    let resp = entorno
        .cliente
        .get(format!("{}/admin/password-policy", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    let resp = entorno
        .cliente
        .put(format!("{}/admin/password-policy", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({
            "min_passphrase_length": 16,
            "min_passphrase_entropy_bits": 60,
            "passphrase_rotation_days": null,
            "generator_default_length": 20,
            "generator_charset_rules": {"uppercase": true, "lowercase": true, "digits": true, "symbols": true, "exclude_ambiguous": true},
            "max_clipboard_clear_minutes": null,
            "max_auto_lock_minutes": null,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn defaults_de_fabrica_coinciden_con_la_spec() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion = common::login(&entorno, &admin).await;

    let resp = entorno
        .cliente
        .get(format!("{}/admin/password-policy", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cuerpo: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["min_passphrase_length"], 12);
    assert_eq!(cuerpo["min_passphrase_entropy_bits"], 60);
    assert_eq!(cuerpo["passphrase_rotation_days"], serde_json::Value::Null);
    assert_eq!(cuerpo["generator_default_length"], 20);
}

#[tokio::test]
async fn no_se_puede_bajar_min_passphrase_length_de_12() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion = common::login(&entorno, &admin).await;

    let resp = entorno
        .cliente
        .put(format!("{}/admin/password-policy", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({
            "min_passphrase_length": 8,
            "min_passphrase_entropy_bits": 60,
            "passphrase_rotation_days": null,
            "generator_default_length": 20,
            "generator_charset_rules": {},
            "max_clipboard_clear_minutes": null,
            "max_auto_lock_minutes": null,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "8 está por debajo del piso de 12, debe rechazarse");
}

#[tokio::test]
async fn admin_actualiza_la_politica_y_persiste() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion = common::login(&entorno, &admin).await;

    let resp = entorno
        .cliente
        .put(format!("{}/admin/password-policy", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({
            "min_passphrase_length": 16,
            "min_passphrase_entropy_bits": 70,
            "passphrase_rotation_days": 90,
            "generator_default_length": 24,
            "generator_charset_rules": {"uppercase": true, "lowercase": true, "digits": true, "symbols": false, "exclude_ambiguous": true},
            "max_clipboard_clear_minutes": 5,
            "max_auto_lock_minutes": 30,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = entorno
        .cliente
        .get(format!("{}/admin/password-policy", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    let cuerpo: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["min_passphrase_length"], 16);
    assert_eq!(cuerpo["passphrase_rotation_days"], 90);
    assert_eq!(cuerpo["max_clipboard_clear_minutes"], 5);
}
