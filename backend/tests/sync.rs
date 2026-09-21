// Autor: Athan Espinoza

//! F-47: `GET /sync?since=<cursor>` — pull incremental de resources/
//! folders/tags contra Postgres real (`testcontainers`, nunca mockeado,
//! mismo criterio que el resto de la suite).

mod common;

use serde_json::{json, Value};
use uuid::Uuid;

async fn crear_recurso(entorno: &common::Entorno, sesion: Uuid) -> Uuid {
    let id = Uuid::now_v7();
    let resp = entorno
        .cliente
        .post(format!("{}/resources", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({
            "id": id,
            "resource_type_slug": "login-password",
            "metadata_ciphertext_b64": "eA==",
            "metadata_nonce_b64": "eA==",
            "sealed_dek_b64": "eA==",
            "secret_ciphertext_b64": "eA==",
            "secret_nonce_b64": "eA==",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    id
}

async fn sync(entorno: &common::Entorno, sesion: Uuid, since: Option<&str>) -> Value {
    let mut req = entorno.cliente.get(format!("{}/sync", entorno.base)).bearer_auth(sesion);
    if let Some(s) = since {
        req = req.query(&[("since", s)]);
    }
    let resp = req.send().await.unwrap();
    assert_eq!(resp.status(), 200);
    resp.json().await.unwrap()
}

#[tokio::test]
async fn sync_completo_devuelve_un_recurso_recien_creado() {
    let entorno = common::levantar().await;
    let alice = common::registrar(&entorno, "alice-sync@test.ellkan").await;
    let sesion = common::login(&entorno, &alice).await;

    let resource_id = crear_recurso(&entorno, sesion).await;

    let cuerpo = sync(&entorno, sesion, None).await;
    let recursos = cuerpo["resources"].as_array().unwrap();
    let item = recursos.iter().find(|r| r["id"] == resource_id.to_string()).expect("el recurso recién creado debe aparecer");
    assert_eq!(item["deleted"], false);
    assert!(item["secret"].is_object(), "debe traer el secret_envelope propio para poder descifrar");
    assert!(cuerpo["cursor"].is_string());
}

#[tokio::test]
async fn sync_incremental_no_repite_lo_ya_sincronizado() {
    let entorno = common::levantar().await;
    let alice = common::registrar(&entorno, "alice-sync-incremental@test.ellkan").await;
    let sesion = common::login(&entorno, &alice).await;

    crear_recurso(&entorno, sesion).await;
    let primer_cursor = sync(&entorno, sesion, None).await["cursor"].as_str().unwrap().to_string();

    // Nada cambió desde ese cursor — la lista debe venir vacía.
    let segundo = sync(&entorno, sesion, Some(&primer_cursor)).await;
    assert!(segundo["resources"].as_array().unwrap().is_empty());

    // Un recurso nuevo SÍ debe aparecer en el próximo pull incremental.
    let nuevo_id = crear_recurso(&entorno, sesion).await;
    let tercero = sync(&entorno, sesion, Some(&primer_cursor)).await;
    let recursos = tercero["resources"].as_array().unwrap();
    assert_eq!(recursos.len(), 1, "sólo el recurso nuevo, no el de antes del cursor");
    assert_eq!(recursos[0]["id"], nuevo_id.to_string());
}

#[tokio::test]
async fn recurso_borrado_aparece_como_tombstone() {
    let entorno = common::levantar().await;
    let alice = common::registrar(&entorno, "alice-sync-tombstone@test.ellkan").await;
    let sesion = common::login(&entorno, &alice).await;

    let resource_id = crear_recurso(&entorno, sesion).await;
    let cursor = sync(&entorno, sesion, None).await["cursor"].as_str().unwrap().to_string();

    let resp = entorno.cliente.delete(format!("{}/resources/{resource_id}", entorno.base)).bearer_auth(sesion).send().await.unwrap();
    assert_eq!(resp.status(), 200);

    let cuerpo = sync(&entorno, sesion, Some(&cursor)).await;
    let recursos = cuerpo["resources"].as_array().unwrap();
    let item = recursos.iter().find(|r| r["id"] == resource_id.to_string()).expect("el borrado debe aparecer como tombstone");
    assert_eq!(item["deleted"], true);
    assert!(item["secret"].is_null());
}

#[tokio::test]
async fn carpeta_creada_y_recurso_movido_aparecen_en_el_sync() {
    let entorno = common::levantar().await;
    let alice = common::registrar(&entorno, "alice-sync-folders@test.ellkan").await;
    let sesion = common::login(&entorno, &alice).await;

    let cursor = sync(&entorno, sesion, None).await["cursor"].as_str().unwrap().to_string();

    let folder_id = Uuid::now_v7();
    let resp = entorno
        .cliente
        .post(format!("{}/folders", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({ "id": folder_id, "name_ciphertext_b64": "eA==", "name_nonce_b64": "eA==", "parent_folder_id": Value::Null }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resource_id = crear_recurso(&entorno, sesion).await;
    let resp = entorno
        .cliente
        .put(format!("{}/resources/{resource_id}/move", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({ "folder_id": folder_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let cuerpo = sync(&entorno, sesion, Some(&cursor)).await;

    let carpetas = cuerpo["folders"].as_array().unwrap();
    let carpeta = carpetas.iter().find(|f| f["folder_id"] == folder_id.to_string()).expect("la carpeta nueva debe aparecer");
    assert_eq!(carpeta["deleted"], false);

    let recursos = cuerpo["resources"].as_array().unwrap();
    let recurso = recursos.iter().find(|r| r["id"] == resource_id.to_string()).expect("el recurso movido debe aparecer");
    assert_eq!(recurso["folder_id"], folder_id.to_string(), "debe traer la carpeta actual aunque el CONTENIDO del recurso no haya cambiado");
}

#[tokio::test]
async fn tag_creado_y_borrado_aparecen_en_el_sync() {
    let entorno = common::levantar().await;
    let alice = common::registrar(&entorno, "alice-sync-tags@test.ellkan").await;
    let sesion = common::login(&entorno, &alice).await;

    let cursor = sync(&entorno, sesion, None).await["cursor"].as_str().unwrap().to_string();

    let tag_id = Uuid::now_v7();
    let resp = entorno
        .cliente
        .post(format!("{}/tags", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({ "id": tag_id, "name": "trabajo", "is_shared": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let cuerpo = sync(&entorno, sesion, Some(&cursor)).await;
    let tags = cuerpo["tags"].as_array().unwrap();
    let tag = tags.iter().find(|t| t["id"] == tag_id.to_string()).expect("el tag nuevo debe aparecer");
    assert_eq!(tag["deleted"], false);
    assert_eq!(tag["name"], "trabajo");

    let cursor2 = cuerpo["cursor"].as_str().unwrap().to_string();
    let resp = entorno.cliente.delete(format!("{}/tags/{tag_id}", entorno.base)).bearer_auth(sesion).send().await.unwrap();
    assert_eq!(resp.status(), 200);

    let cuerpo2 = sync(&entorno, sesion, Some(&cursor2)).await;
    let tags2 = cuerpo2["tags"].as_array().unwrap();
    let tag2 = tags2.iter().find(|t| t["id"] == tag_id.to_string()).expect("el borrado debe aparecer como tombstone");
    assert_eq!(tag2["deleted"], true);
}

#[tokio::test]
async fn borrar_una_carpeta_no_vacia_se_rechaza() {
    let entorno = common::levantar().await;
    let alice = common::registrar(&entorno, "alice-borrar-carpeta@test.ellkan").await;
    let sesion = common::login(&entorno, &alice).await;

    let folder_id = Uuid::now_v7();
    entorno
        .cliente
        .post(format!("{}/folders", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({ "id": folder_id, "name_ciphertext_b64": "eA==", "name_nonce_b64": "eA==", "parent_folder_id": Value::Null }))
        .send()
        .await
        .unwrap();

    let resource_id = crear_recurso(&entorno, sesion).await;
    entorno
        .cliente
        .put(format!("{}/resources/{resource_id}/move", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({ "folder_id": folder_id }))
        .send()
        .await
        .unwrap();

    let resp = entorno.cliente.delete(format!("{}/folders/{folder_id}", entorno.base)).bearer_auth(sesion).send().await.unwrap();
    assert_eq!(resp.status(), 400, "una carpeta con un recurso adentro no debe poder borrarse");

    // Vaciarla primero (sacar el recurso a la raíz) sí permite borrarla.
    entorno
        .cliente
        .put(format!("{}/resources/{resource_id}/move", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({ "folder_id": Value::Null }))
        .send()
        .await
        .unwrap();
    let resp = entorno.cliente.delete(format!("{}/folders/{folder_id}", entorno.base)).bearer_auth(sesion).send().await.unwrap();
    assert_eq!(resp.status(), 200, "una carpeta vacía sí debe poder borrarse");
}
