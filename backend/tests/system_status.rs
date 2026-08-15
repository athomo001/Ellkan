// Autor: Athan Espinoza

//! F-43: panel de autodiagnóstico admin — sólo admin puede leerlo, y la
//! respuesta siempre trae los 5 grupos (base_datos/correo/integraciones/
//! seguridad/organizacion) con el check de DB en `ok` (el mismo Postgres
//! que sostiene el test está respondiendo).

mod common;

use serde_json::Value;

#[tokio::test]
async fn sin_admin_no_puede_leer_el_estado_del_sistema() {
    let entorno = common::levantar().await;
    let user = common::registrar(&entorno, "system-status-sin-admin@test.ellkan").await;
    let sesion = common::login(&entorno, &user).await;

    let resp = entorno
        .cliente
        .get(format!("{}/admin/system-status", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn admin_ve_los_grupos_de_checks_con_la_db_en_ok() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "system-status-admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion = common::login(&entorno, &admin).await;

    let resp = entorno
        .cliente
        .get(format!("{}/admin/system-status", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cuerpo: Value = resp.json().await.unwrap();
    let grupos = cuerpo.as_array().unwrap();

    let categorias: Vec<&str> = grupos.iter().map(|g| g["categoria"].as_str().unwrap()).collect();
    assert_eq!(categorias, vec!["base_datos", "correo", "integraciones", "seguridad", "organizacion"]);

    let grupo_db = grupos.iter().find(|g| g["categoria"] == "base_datos").unwrap();
    let check_ping = grupo_db["checks"].as_array().unwrap().iter().find(|c| c["id"] == "db_ping").unwrap();
    assert_eq!(check_ping["nivel"], "ok", "la DB que sostiene el test debe reportarse como ok");

    // Hallazgo real de uso: `claves_activas == 0` tiene que avisar (no hay
    // forma de compartir nada todavía), no reportarse como "ok" silencioso.
    let grupo_seguridad = grupos.iter().find(|g| g["categoria"] == "seguridad").unwrap();
    let check_metadata = grupo_seguridad["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "metadata_key_rotacion")
        .unwrap();
    assert_eq!(check_metadata["claves_activas"], 0);
    assert_eq!(check_metadata["nivel"], "advertencia", "sin ninguna metadata key, esto no puede ser 'ok'");

    // El admin recién promovido cuenta como admin activo.
    let grupo_org = grupos.iter().find(|g| g["categoria"] == "organizacion").unwrap();
    let check_admins = grupo_org["checks"].as_array().unwrap().iter().find(|c| c["id"] == "admins_activos").unwrap();
    assert_eq!(check_admins["nivel"], "ok");
    assert!(check_admins["cantidad"].as_i64().unwrap() >= 1);

    // Ningún check filtra secretos — ni el ciphertext/host de SMTP, ni la
    // bind_password de LDAP, ni ningún token.
    let cuerpo_texto = cuerpo.to_string();
    assert!(!cuerpo_texto.contains("password"), "el endpoint no debe exponer ningún campo de contraseña/secreto");
}
