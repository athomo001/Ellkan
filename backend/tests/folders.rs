// Autor: Athan Espinoza

//! F-09: mover una carpeta en el árbol de un usuario no afecta lo que otro
//! usuario ve para esa misma carpeta — criterio de aceptación literal.
//! F-11: mover un RECURSO a una carpeta compartida exige `update` sobre
//! ella y nunca comparte el recurso automáticamente; compartir una carpeta
//! exige `owner`.

mod common;

use serde_json::{json, Value};
use uuid::Uuid;

async fn crear_carpeta(entorno: &common::Entorno, sesion: Uuid, parent: Option<Uuid>) -> Uuid {
    let id = Uuid::now_v7();
    let resp = entorno
        .cliente
        .post(format!("{}/folders", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({
            "id": id,
            "name_ciphertext_b64": "eA==",
            "name_nonce_b64": "eA==",
            "parent_folder_id": parent,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    id
}

async fn crear_recurso_simple(entorno: &common::Entorno, sesion: Uuid) -> Uuid {
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
    assert_eq!(resp.status(), 200, "crear recurso debería devolver 200");
    id
}

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

#[tokio::test]
async fn mover_recurso_a_carpeta_propia_funciona_y_filtra_el_listado() {
    let entorno = common::levantar().await;
    let alice = common::registrar(&entorno, "alice-folders-3@test.ellkan").await;
    let sesion_alice = common::login(&entorno, &alice).await;

    let folder_id = crear_carpeta(&entorno, sesion_alice, None).await;
    let resource_id = crear_recurso_simple(&entorno, sesion_alice).await;

    let resp = entorno
        .cliente
        .put(format!("{}/resources/{resource_id}/move", entorno.base))
        .bearer_auth(sesion_alice)
        .json(&json!({ "folder_id": folder_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = entorno
        .cliente
        .get(format!("{}/resources?folder_id={folder_id}", entorno.base))
        .bearer_auth(sesion_alice)
        .send()
        .await
        .unwrap();
    let listado: Value = resp.json().await.unwrap();
    assert!(listado.as_array().unwrap().iter().any(|r| r["id"] == json!(resource_id)));

    // Sacarlo de la carpeta (folder_id: null) lo vuelve a la raíz.
    let resp = entorno
        .cliente
        .put(format!("{}/resources/{resource_id}/move", entorno.base))
        .bearer_auth(sesion_alice)
        .json(&json!({ "folder_id": null }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = entorno
        .cliente
        .get(format!("{}/resources?folder_id={folder_id}", entorno.base))
        .bearer_auth(sesion_alice)
        .send()
        .await
        .unwrap();
    let listado: Value = resp.json().await.unwrap();
    assert!(listado.as_array().unwrap().iter().all(|r| r["id"] != json!(resource_id)));
}

#[tokio::test]
async fn compartir_carpeta_exige_owner_y_mover_recurso_exige_update() {
    let entorno = common::levantar().await;
    let alice = common::registrar(&entorno, "alice-folders-4@test.ellkan").await;
    let bob = common::registrar(&entorno, "bob-folders-4@test.ellkan").await;
    let sesion_alice = common::login(&entorno, &alice).await;
    let sesion_bob = common::login(&entorno, &bob).await;

    let folder_id = crear_carpeta(&entorno, sesion_alice, None).await;

    // Bob (sin ningún permiso sobre la carpeta) no puede compartirla.
    let resp = entorno
        .cliente
        .post(format!("{}/folders/{folder_id}/share", entorno.base))
        .bearer_auth(sesion_bob)
        .json(&json!({
            "grantee_user_id": bob.user_id,
            "level": "read",
            "name_ciphertext_b64": "eA==",
            "name_nonce_b64": "eA==",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Alice (Owner por ser la creadora) comparte con Bob a nivel `read`.
    let resp = entorno
        .cliente
        .post(format!("{}/folders/{folder_id}/share", entorno.base))
        .bearer_auth(sesion_alice)
        .json(&json!({
            "grantee_user_id": bob.user_id,
            "level": "read",
            "name_ciphertext_b64": "eA==",
            "name_nonce_b64": "eA==",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Bob ahora ve la carpeta en su propio árbol.
    let resp = entorno.cliente.get(format!("{}/folders", entorno.base)).bearer_auth(sesion_bob).send().await.unwrap();
    let arbol_bob: Value = resp.json().await.unwrap();
    assert!(arbol_bob.as_array().unwrap().iter().any(|n| n["folder_id"] == json!(folder_id)));

    // Con sólo `read`, Bob no puede mover un recurso propio hacia la carpeta de Alice.
    let recurso_bob = crear_recurso_simple(&entorno, sesion_bob).await;
    let resp = entorno
        .cliente
        .put(format!("{}/resources/{recurso_bob}/move", entorno.base))
        .bearer_auth(sesion_bob)
        .json(&json!({ "folder_id": folder_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "read no alcanza para mover cosas hacia la carpeta");

    // Alice sube el nivel de Bob a `update` — ahora sí puede.
    let resp = entorno
        .cliente
        .post(format!("{}/folders/{folder_id}/share", entorno.base))
        .bearer_auth(sesion_alice)
        .json(&json!({
            "grantee_user_id": bob.user_id,
            "level": "update",
            "name_ciphertext_b64": "eA==",
            "name_nonce_b64": "eA==",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = entorno
        .cliente
        .put(format!("{}/resources/{recurso_bob}/move", entorno.base))
        .bearer_auth(sesion_bob)
        .json(&json!({ "folder_id": folder_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "update sí alcanza para mover cosas hacia la carpeta");

    // Moverlo a la carpeta compartida no le da a Alice acceso al secreto del
    // recurso de Bob — compartir sigue siendo un paso aparte, nunca un
    // efecto colateral de mover (zero-knowledge: el servidor no puede
    // otorgar acceso a un secreto cifrado).
    let resp = entorno
        .cliente
        .get(format!("{}/resources/{recurso_bob}/secret", entorno.base))
        .bearer_auth(sesion_alice)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "mover a una carpeta compartida nunca comparte el recurso en sí");
}

#[tokio::test]
async fn mover_recurso_a_carpeta_personal_de_otro_falla() {
    let entorno = common::levantar().await;
    let alice = common::registrar(&entorno, "alice-folders-5@test.ellkan").await;
    let bob = common::registrar(&entorno, "bob-folders-5@test.ellkan").await;
    let sesion_alice = common::login(&entorno, &alice).await;
    let sesion_bob = common::login(&entorno, &bob).await;

    let folder_id = crear_carpeta(&entorno, sesion_alice, None).await;
    let recurso_bob = crear_recurso_simple(&entorno, sesion_bob).await;

    // La carpeta de Alice nunca se compartió — Bob ni siquiera la tiene en
    // su árbol, así que no puede moverle nada.
    let resp = entorno
        .cliente
        .put(format!("{}/resources/{recurso_bob}/move", entorno.base))
        .bearer_auth(sesion_bob)
        .json(&json!({ "folder_id": folder_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}
