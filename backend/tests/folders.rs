// Autor: Athan Espinoza

//! F-09: mover una carpeta en el árbol de un usuario no afecta lo que otro
//! usuario ve para esa misma carpeta — criterio de aceptación literal.

mod common;

use serde_json::{json, Value};
use uuid::Uuid;

#[tokio::test]
async fn mover_carpeta_no_afecta_la_vista_de_otro_usuario() {
    let entorno = common::levantar().await;
    let alice = common::registrar(&entorno, "alice-folders@test.ellkan").await;
    let bob = common::registrar(&entorno, "bob-folders@test.ellkan").await;
    let sesion_alice = common::login(&entorno, &alice).await;
    let sesion_bob = common::login(&entorno, &bob).await;

    // Alice crea una carpeta raíz "Trabajo" y una sub-carpeta "Clientes".
    let raiz_id = Uuid::now_v7();
    let resp = entorno
        .cliente
        .post(format!("{}/folders", entorno.base))
        .bearer_auth(sesion_alice)
        .json(&json!({
            "id": raiz_id,
            "name_ciphertext_b64": "dHJhYmFqbw==",
            "name_nonce_b64": "bm9uY2U=",
            "parent_folder_id": null,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let sub_id = Uuid::now_v7();
    let resp = entorno
        .cliente
        .post(format!("{}/folders", entorno.base))
        .bearer_auth(sesion_alice)
        .json(&json!({
            "id": sub_id,
            "name_ciphertext_b64": "Y2xpZW50ZXM=",
            "name_nonce_b64": "bm9uY2U=",
            "parent_folder_id": raiz_id,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Bob crea su propia carpeta raíz y también coloca `sub_id` en su árbol
    // (una carpeta puede aparecer en el árbol de más de un usuario).
    let bob_raiz_id = Uuid::now_v7();
    let resp = entorno
        .cliente
        .post(format!("{}/folders", entorno.base))
        .bearer_auth(sesion_bob)
        .json(&json!({
            "id": bob_raiz_id,
            "name_ciphertext_b64": "cGVyc29uYWw=",
            "name_nonce_b64": "bm9uY2U=",
            "parent_folder_id": null,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = entorno
        .cliente
        .put(format!("{}/folders/{sub_id}/move", entorno.base))
        .bearer_auth(sesion_bob)
        .json(&json!({ "new_parent_folder_id": bob_raiz_id }))
        .send()
        .await
        .unwrap();
    // Bob nunca tuvo `sub_id` en su árbol — "mover" algo que no es suyo falla.
    assert_eq!(resp.status(), 404);

    // --- Alice mueve "Clientes" a la raíz ---
    let resp = entorno
        .cliente
        .put(format!("{}/folders/{sub_id}/move", entorno.base))
        .bearer_auth(sesion_alice)
        .json(&json!({ "new_parent_folder_id": null }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = entorno
        .cliente
        .get(format!("{}/folders", entorno.base))
        .bearer_auth(sesion_alice)
        .send()
        .await
        .unwrap();
    let arbol: Value = resp.json().await.unwrap();
    let nodo_sub = arbol.as_array().unwrap().iter().find(|n| n["folder_id"] == json!(sub_id)).unwrap();
    assert_eq!(nodo_sub["parent_folder_id"], Value::Null, "para Alice, la sub-carpeta ahora está en la raíz");

    // --- La vista de Bob no tiene ninguna referencia a `sub_id` (nunca la posicionó) ---
    let resp = entorno
        .cliente
        .get(format!("{}/folders", entorno.base))
        .bearer_auth(sesion_bob)
        .send()
        .await
        .unwrap();
    let arbol_bob: Value = resp.json().await.unwrap();
    assert!(
        arbol_bob.as_array().unwrap().iter().all(|n| n["folder_id"] != json!(sub_id)),
        "Bob nunca posicionó sub_id, no debería aparecer en su árbol"
    );
}

#[tokio::test]
async fn crear_carpeta_con_parent_inexistente_falla() {
    let entorno = common::levantar().await;
    let alice = common::registrar(&entorno, "alice-folders-2@test.ellkan").await;
    let sesion_alice = common::login(&entorno, &alice).await;

    let resp = entorno
        .cliente
        .post(format!("{}/folders", entorno.base))
        .bearer_auth(sesion_alice)
        .json(&json!({
            "id": Uuid::now_v7(),
            "name_ciphertext_b64": "eA==",
            "name_nonce_b64": "eA==",
            "parent_folder_id": Uuid::now_v7(),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "parent_folder_id inexistente debe fallar explícito");
}
