// Autor: Athan Espinoza

//! F-30/F-31/F-39: `GET/PUT /me/preferences` — cada usuario lee/cambia sólo
//! las suyas, los defaults de fábrica coinciden con la spec, y un techo de
//! `password_policy` fijado por un admin se respeta.

mod common;

use serde_json::json;

#[tokio::test]
async fn defaults_de_fabrica_coinciden_con_la_spec() {
    let entorno = common::levantar().await;
    let user = common::registrar(&entorno, "alice@test.ellkan").await;
    let sesion = common::login(&entorno, &user).await;

    let resp = entorno
        .cliente
        .get(format!("{}/me/preferences", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cuerpo: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["locale"], "es");
    assert_eq!(cuerpo["theme"], "dark");
    assert_eq!(cuerpo["clipboard_clear_minutes"], 1);
    assert_eq!(cuerpo["auto_lock_minutes"], 15);
}

#[tokio::test]
async fn actualizar_persiste_y_es_propia_de_cada_usuario() {
    let entorno = common::levantar().await;
    let alice = common::registrar(&entorno, "alice@test.ellkan").await;
    let sesion_alice = common::login(&entorno, &alice).await;
    let bob = common::registrar(&entorno, "bob@test.ellkan").await;
    let sesion_bob = common::login(&entorno, &bob).await;

    let resp = entorno
        .cliente
        .put(format!("{}/me/preferences", entorno.base))
        .bearer_auth(sesion_alice)
        .json(&json!({
            "locale": "en",
            "theme": "light",
            "clipboard_clear_minutes": 3,
            "auto_lock_minutes": 45,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = entorno
        .cliente
        .get(format!("{}/me/preferences", entorno.base))
        .bearer_auth(sesion_alice)
        .send()
        .await
        .unwrap();
    let cuerpo: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["locale"], "en");
    assert_eq!(cuerpo["clipboard_clear_minutes"], 3);

    // Bob nunca tocó las suyas — siguen en el default de fábrica.
    let resp = entorno
        .cliente
        .get(format!("{}/me/preferences", entorno.base))
        .bearer_auth(sesion_bob)
        .send()
        .await
        .unwrap();
    let cuerpo: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["locale"], "es");
    assert_eq!(cuerpo["clipboard_clear_minutes"], 1);
}

#[tokio::test]
async fn locale_invalido_se_rechaza() {
    let entorno = common::levantar().await;
    let user = common::registrar(&entorno, "alice@test.ellkan").await;
    let sesion = common::login(&entorno, &user).await;

    let resp = entorno
        .cliente
        .put(format!("{}/me/preferences", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({
            "locale": "fr",
            "theme": "dark",
            "clipboard_clear_minutes": 1,
            "auto_lock_minutes": 15,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn techo_de_password_policy_se_respeta() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    let resp = entorno
        .cliente
        .put(format!("{}/admin/password-policy", entorno.base))
        .bearer_auth(sesion_admin)
        .json(&json!({
            "min_passphrase_length": 12,
            "min_passphrase_entropy_bits": 60,
            "passphrase_rotation_days": null,
            "generator_default_length": 20,
            "generator_charset_rules": {},
            "max_clipboard_clear_minutes": 2,
            "max_auto_lock_minutes": 30,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let user = common::registrar(&entorno, "alice@test.ellkan").await;
    let sesion = common::login(&entorno, &user).await;

    let resp = entorno
        .cliente
        .put(format!("{}/me/preferences", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({
            "locale": "es",
            "theme": "dark",
            "clipboard_clear_minutes": 5,
            "auto_lock_minutes": 15,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "5 supera el techo de 2 fijado por el admin");
}
