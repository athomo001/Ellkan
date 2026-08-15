// Autor: Athan Espinoza

//! F-22 (RBAC, groundwork adelantado): `AdminUser` rechaza a un usuario sin
//! permiso `"*"`, y un admin puede crear un rol custom cuyos permisos
//! persisten — el ejemplo `auditor` explícitamente pedido por F-22 ya viene
//! sembrado por la migración, acá se prueba el camino de crear uno nuevo.

mod common;

use serde_json::{json, Value};

#[tokio::test]
async fn usuario_sin_rol_admin_recibe_403_en_endpoints_de_roles() {
    let entorno = common::levantar().await;
    let user = common::registrar(&entorno, "sin-admin@test.ellkan").await;
    let sesion = common::login(&entorno, &user).await;

    let resp = entorno
        .cliente
        .get(format!("{}/admin/roles", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "GET /admin/roles debe exigir permiso admin");

    let resp = entorno
        .cliente
        .post(format!("{}/admin/roles", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({ "name": "otro-rol", "permissions": [] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "POST /admin/roles debe exigir permiso admin");
}

#[tokio::test]
async fn admin_crea_rol_custom_y_sus_permisos_persisten() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion = common::login(&entorno, &admin).await;

    let resp = entorno
        .cliente
        .post(format!("{}/admin/roles", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({ "name": "helpdesk", "permissions": ["mfa.reset"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "un admin sí puede crear un rol custom");
    let cuerpo: Value = resp.json().await.unwrap();
    let role_id = cuerpo["id"].as_str().unwrap();
    assert_eq!(cuerpo["permissions"], json!(["mfa.reset"]));

    let resp = entorno
        .cliente
        .get(format!("{}/admin/roles", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let roles: Value = resp.json().await.unwrap();
    let nombres: Vec<&str> = roles.as_array().unwrap().iter().map(|r| r["name"].as_str().unwrap()).collect();
    assert!(nombres.contains(&"admin"), "el rol admin sembrado por la migración debe listarse");
    assert!(nombres.contains(&"auditor"), "el rol auditor de ejemplo (F-22) debe listarse");
    assert!(nombres.contains(&"helpdesk"), "el rol recién creado debe listarse");

    let resp = entorno
        .cliente
        .put(format!("{}/admin/roles/{role_id}", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({ "permissions": ["mfa.reset", "users.view"] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["permissions"], json!(["mfa.reset", "users.view"]));
}
