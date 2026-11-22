// Autor: Athan Espinoza

//! Pendiente #57: el admin carga los links de privacidad y términos, y
//! `GET /auth/setup-status` los muestra sin sesión (registro y login).

mod common;

use serde_json::{Value, json};

#[tokio::test]
async fn el_admin_carga_los_links_y_el_registro_los_ve() {
    let entorno = common::levantar().await;
    let estado = |entorno: &common::Entorno| {
        let pedido = entorno.cliente.get(format!("{}/auth/setup-status", entorno.base)).send();
        async move { pedido.await.unwrap().json::<Value>().await.unwrap() }
    };
    let s = estado(&entorno).await;
    assert_eq!(s["privacy_url"], Value::Null, "vacíos por defecto");
    assert_eq!(s["terms_url"], Value::Null);

    let admin = common::registrar(&entorno, "admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;
    let comun = common::registrar(&entorno, "comun@test.ellkan").await;
    let sesion_comun = common::login(&entorno, &comun).await;
    let ruta = format!("{}/admin/legal-links", entorno.base);

    let resp = entorno
        .cliente
        .put(&ruta)
        .bearer_auth(sesion_comun)
        .json(&json!({ "privacy_url": "https://x.cl" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // El frontend lo pone en un `href`: sólo http(s).
    let resp = entorno
        .cliente
        .put(&ruta)
        .bearer_auth(sesion_admin)
        .json(&json!({ "privacy_url": "javascript:alert(1)" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    let resp = entorno
        .cliente
        .put(&ruta)
        .bearer_auth(sesion_admin)
        .json(&json!({ "privacy_url": " https://empresa.cl/privacidad ", "terms_url": "" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["privacy_url"], "https://empresa.cl/privacidad");
    assert_eq!(cuerpo["terms_url"], Value::Null);

    let s = estado(&entorno).await;
    assert_eq!(s["privacy_url"], "https://empresa.cl/privacidad");
    assert_eq!(s["terms_url"], Value::Null);

    let leido: Value = entorno.cliente.get(&ruta).bearer_auth(sesion_admin).send().await.unwrap().json().await.unwrap();
    assert_eq!(leido["privacy_url"], "https://empresa.cl/privacidad");

    let mut eventos = 0i64;
    for _ in 0..50 {
        (eventos,) = sqlx::query_as("select count(*) from audit_log_entries where event_type = 'legal_links.updated'")
            .fetch_one(&entorno.pool)
            .await
            .unwrap();
        if eventos > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(eventos, 1);
}
