// Autor: Athan Espinoza

//! Pendiente #89 (F-43): el aviso de versión nueva está apagado por defecto,
//! sólo un admin lo cambia, y al activarlo el servidor lee la última versión
//! de la URL de consulta (acá un GitHub falso local, nunca internet).

mod common;

use serde_json::{Value, json};

/// Un "GitHub" de mentira en un puerto local que contesta una Release.
async fn github_falso() -> String {
    let app = axum::Router::new().route(
        "/releases/latest",
        axum::routing::get(|| async {
            axum::Json(json!({
                "tag_name": "v9.9.9",
                "html_url": "https://github.com/athomo001/ellkan/releases/tag/v9.9.9",
                "body": "notas"
            }))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dir = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{dir}/releases/latest")
}

#[tokio::test]
async fn apagado_por_defecto_y_al_activarlo_lee_la_ultima_version() {
    // Antes de levantar el servidor: la URL se lee en cada consulta.
    let url = github_falso().await;
    unsafe {
        std::env::set_var("ELLKAN_UPDATE_CHECK_URL", &url);
    }

    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;
    let comun = common::registrar(&entorno, "comun@test.ellkan").await;
    let sesion_comun = common::login(&entorno, &comun).await;

    let ruta = format!("{}/admin/update-check", entorno.base);
    let estado: Value = entorno.cliente.get(&ruta).bearer_auth(sesion_admin).send().await.unwrap().json().await.unwrap();
    assert_eq!(estado["enabled"], false, "apagado por defecto: Ellkan no llama a casa solo");
    assert_eq!(estado["latest_version"], Value::Null);
    assert_eq!(estado["update_available"], false);

    // Un usuario común no lo ve ni lo cambia.
    let resp = entorno.cliente.get(&ruta).bearer_auth(sesion_comun).send().await.unwrap();
    assert_eq!(resp.status(), 403);
    let resp = entorno
        .cliente
        .put(&ruta)
        .bearer_auth(sesion_comun)
        .json(&json!({ "enabled": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    let resp = entorno
        .cliente
        .put(&ruta)
        .bearer_auth(sesion_admin)
        .json(&json!({ "enabled": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["enabled"], true);

    // La consulta corre en segundo plano.
    let mut estado = Value::Null;
    for _ in 0..50 {
        estado = entorno.cliente.get(&ruta).bearer_auth(sesion_admin).send().await.unwrap().json().await.unwrap();
        if estado["latest_version"] != Value::Null {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(estado["latest_version"], "9.9.9");
    assert_eq!(estado["release_url"], "https://github.com/athomo001/ellkan/releases/tag/v9.9.9");
    assert!(estado["checked_at"].is_string());
    // Un build de test no tiene número de versión: no compara.
    assert_eq!(estado["current_version"], Value::Null);
    assert_eq!(estado["update_available"], false);

    // Queda en la auditoría.
    let mut eventos = 0i64;
    for _ in 0..50 {
        (eventos,) = sqlx::query_as("select count(*) from audit_log_entries where event_type = 'update_check.updated'")
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
