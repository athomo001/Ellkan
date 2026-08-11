// Autor: Athan Espinoza

//! F-11/F-12, hallazgo real de uso 2026-08-11: grupos como unidad de
//! trabajo real. Criterios de aceptación literales cubiertos acá:
//! - un usuario sin ningún grupo no ve a nadie en `/users/search`; con
//!   grupo, sólo ve a su propio grupo; un admin de grupo ve además a
//!   cualquier otro admin de grupo y al admin de organización.
//! - un usuario regular no puede anidar ni compartir carpetas; un admin de
//!   grupo (o de organización) anida hasta profundidad 3, falla en la 4.
//! - ciclos en el árbol de carpetas se rechazan (bug latente real
//!   encontrado en el camino, antes no había ningún chequeo).
//! - cualquier miembro de un grupo puede agregar un recurso a una carpeta
//!   compartida con ese grupo (no hace falta `update` sobre la carpeta).
//! - `DELETE /resources/{id}` (endpoint nuevo): en una carpeta de grupo,
//!   sólo admin de ese grupo o admin de organización — ni siquiera el
//!   `owner` individual del recurso alcanza; fuera de una carpeta de
//!   grupo, el `owner` de siempre alcanza.
//! - `GET /resources?folder_id=X&incluir_subcarpetas=true` trae también
//!   los recursos de las subcarpetas.

mod common;

use serde_json::{json, Value};
use uuid::Uuid;

async fn crear_grupo(entorno: &common::Entorno, sesion_admin: Uuid, name: &str) -> Uuid {
    let id = Uuid::now_v7();
    let resp = entorno
        .cliente
        .post(format!("{}/groups", entorno.base))
        .bearer_auth(sesion_admin)
        .json(&json!({ "id": id, "name": name }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "crear grupo debería devolver 200");
    id
}

async fn agregar_miembro(entorno: &common::Entorno, sesion_actor: Uuid, group_id: Uuid, user_id: Uuid, is_admin: bool) {
    let resp = entorno
        .cliente
        .post(format!("{}/groups/{group_id}/members/{user_id}", entorno.base))
        .bearer_auth(sesion_actor)
        .json(&json!({ "is_admin": is_admin, "envelopes": [] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "agregar miembro debería devolver 200");
}

async fn crear_carpeta(entorno: &common::Entorno, sesion: Uuid, parent: Option<Uuid>) -> reqwest::Response {
    let id = Uuid::now_v7();
    entorno
        .cliente
        .post(format!("{}/folders", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({ "id": id, "name_ciphertext_b64": "eA==", "name_nonce_b64": "eA==", "parent_folder_id": parent }))
        .send()
        .await
        .unwrap()
}

async fn crear_carpeta_ok(entorno: &common::Entorno, sesion: Uuid, parent: Option<Uuid>) -> Uuid {
    let resp = crear_carpeta(entorno, sesion, parent).await;
    assert_eq!(resp.status(), 200, "crear carpeta debería devolver 200");
    let cuerpo: Value = resp.json().await.unwrap();
    cuerpo["folder_id"].as_str().unwrap().parse().unwrap()
}

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

async fn mover_recurso(entorno: &common::Entorno, sesion: Uuid, resource_id: Uuid, folder_id: Option<Uuid>) -> reqwest::Response {
    entorno
        .cliente
        .put(format!("{}/resources/{resource_id}/move", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({ "folder_id": folder_id }))
        .send()
        .await
        .unwrap()
}

async fn buscar(entorno: &common::Entorno, sesion: Uuid, q: &str) -> Vec<Value> {
    let resp = entorno
        .cliente
        .get(format!("{}/users/search?q={q}", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    resp.json::<Value>().await.unwrap().as_array().unwrap().clone()
}

fn contiene_email(resultados: &[Value], email: &str) -> bool {
    resultados.iter().any(|u| u["email"] == email)
}

#[tokio::test]
async fn visibilidad_de_usuarios_acotada_por_grupo() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "gc-admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    let alice = common::registrar(&entorno, "gc-alice@test.ellkan").await; // sin grupo
    let _bob = common::registrar(&entorno, "gc-bob@test.ellkan").await; // sin grupo
    let carol = common::registrar(&entorno, "gc-carol@test.ellkan").await;
    let dave = common::registrar(&entorno, "gc-dave@test.ellkan").await; // admin de G1
    let eve = common::registrar(&entorno, "gc-eve@test.ellkan").await; // admin de G2
    let sesion_alice = common::login(&entorno, &alice).await;
    let sesion_carol = common::login(&entorno, &carol).await;
    let sesion_dave = common::login(&entorno, &dave).await;

    let g1 = crear_grupo(&entorno, sesion_admin, "G1").await;
    agregar_miembro(&entorno, sesion_admin, g1, carol.user_id, false).await;
    agregar_miembro(&entorno, sesion_admin, g1, dave.user_id, true).await;
    let g2 = crear_grupo(&entorno, sesion_admin, "G2").await;
    agregar_miembro(&entorno, sesion_admin, g2, eve.user_id, true).await;

    // Alice no tiene ningún grupo: no ve a nadie más (ni siquiera a bob, que tampoco tiene grupo).
    let resultados = buscar(&entorno, sesion_alice, "gc-bob").await;
    assert!(!contiene_email(&resultados, "gc-bob@test.ellkan"), "sin grupo, alice no debería ver a bob");

    // Carol ve a Dave (mismo grupo G1) pero no a Alice (grupos distintos/ninguno).
    let resultados = buscar(&entorno, sesion_carol, "gc-dave").await;
    assert!(contiene_email(&resultados, "gc-dave@test.ellkan"), "carol debería ver a dave, mismo grupo");
    let resultados = buscar(&entorno, sesion_carol, "gc-alice").await;
    assert!(!contiene_email(&resultados, "gc-alice@test.ellkan"), "carol no debería ver a alice, grupos distintos");

    // Dave es admin de grupo: ve a Eve (admin de OTRO grupo) aunque no comparten grupo.
    let resultados = buscar(&entorno, sesion_dave, "gc-eve").await;
    assert!(contiene_email(&resultados, "gc-eve@test.ellkan"), "un admin de grupo debería ver a admins de otros grupos");
    // Pero Dave no ve a Alice (regular, sin grupo, no admin de nada).
    let resultados = buscar(&entorno, sesion_dave, "gc-alice").await;
    assert!(!contiene_email(&resultados, "gc-alice@test.ellkan"), "un admin de grupo no ve a un regular de otro/ningún grupo");

    // El admin de organización ve a cualquiera.
    let resultados = buscar(&entorno, sesion_admin, "gc-alice").await;
    assert!(contiene_email(&resultados, "gc-alice@test.ellkan"), "el admin de organización ve a todos");
}

#[tokio::test]
async fn anidacion_de_carpetas_exige_privilegio_y_respeta_profundidad_3() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "gc-carpetas-admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    let alice = common::registrar(&entorno, "gc-carpetas-alice@test.ellkan").await;
    let dave = common::registrar(&entorno, "gc-carpetas-dave@test.ellkan").await;
    let sesion_alice = common::login(&entorno, &alice).await;
    let sesion_dave = common::login(&entorno, &dave).await;

    let g1 = crear_grupo(&entorno, sesion_admin, "G-carpetas").await;
    agregar_miembro(&entorno, sesion_admin, g1, dave.user_id, true).await;

    // Alice (regular): puede crear una carpeta raíz, pero no anidar.
    let raiz_alice = crear_carpeta_ok(&entorno, sesion_alice, None).await;
    let resp = crear_carpeta(&entorno, sesion_alice, Some(raiz_alice)).await;
    assert_eq!(resp.status(), 403, "un usuario regular no debería poder anidar carpetas");

    // Dave (admin de grupo): anida hasta profundidad 3, falla en la 4.
    let n1 = crear_carpeta_ok(&entorno, sesion_dave, None).await; // profundidad 1
    let n2 = crear_carpeta_ok(&entorno, sesion_dave, Some(n1)).await; // profundidad 2
    let n3 = crear_carpeta_ok(&entorno, sesion_dave, Some(n2)).await; // profundidad 3
    let resp = crear_carpeta(&entorno, sesion_dave, Some(n3)).await; // profundidad 4
    assert_eq!(resp.status(), 400, "profundidad 4 debería exceder el máximo (3)");
}

#[tokio::test]
async fn mover_carpeta_a_su_propio_descendiente_es_un_ciclo_rechazado() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "gc-ciclo-admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    let dave = common::registrar(&entorno, "gc-ciclo-dave@test.ellkan").await;
    let sesion_dave = common::login(&entorno, &dave).await;
    let g1 = crear_grupo(&entorno, sesion_admin, "G-ciclo").await;
    agregar_miembro(&entorno, sesion_admin, g1, dave.user_id, true).await;

    let a = crear_carpeta_ok(&entorno, sesion_dave, None).await;
    let b = crear_carpeta_ok(&entorno, sesion_dave, Some(a)).await;

    // Mover A (ancestro) para que quede dentro de B (su propio descendiente) es un ciclo.
    let resp = entorno
        .cliente
        .put(format!("{}/folders/{a}/move", entorno.base))
        .bearer_auth(sesion_dave)
        .json(&json!({ "new_parent_folder_id": b }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "mover una carpeta dentro de su propio descendiente debería rechazarse como ciclo");
}

#[tokio::test]
async fn cualquier_miembro_agrega_recursos_a_carpeta_de_grupo_pero_no_un_ajeno() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "gc-agregar-admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    let dave = common::registrar(&entorno, "gc-agregar-dave@test.ellkan").await; // admin del grupo
    let carol = common::registrar(&entorno, "gc-agregar-carol@test.ellkan").await; // miembro regular
    let eve = common::registrar(&entorno, "gc-agregar-eve@test.ellkan").await; // ajena al grupo
    let sesion_dave = common::login(&entorno, &dave).await;
    let sesion_carol = common::login(&entorno, &carol).await;
    let sesion_eve = common::login(&entorno, &eve).await;

    let g1 = crear_grupo(&entorno, sesion_admin, "G-agregar").await;
    agregar_miembro(&entorno, sesion_admin, g1, dave.user_id, true).await;
    agregar_miembro(&entorno, sesion_admin, g1, carol.user_id, false).await;

    let folder_id = crear_carpeta_ok(&entorno, sesion_dave, None).await;
    let resp = entorno
        .cliente
        .post(format!("{}/folders/{folder_id}/share", entorno.base))
        .bearer_auth(sesion_dave)
        .json(&json!({
            "grantee_type": "group",
            "grantee_id": g1,
            "level": "read",
            "member_envelopes": [
                { "user_id": dave.user_id, "name_ciphertext_b64": "eA==", "name_nonce_b64": "eA==" },
                { "user_id": carol.user_id, "name_ciphertext_b64": "eA==", "name_nonce_b64": "eA==" },
            ],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "compartir la carpeta con el grupo entero debería funcionar");

    // Carol (regular, sin `update` individual sobre la carpeta) puede agregar su propio recurso.
    let recurso_carol = crear_recurso(&entorno, sesion_carol).await;
    let resp = mover_recurso(&entorno, sesion_carol, recurso_carol, Some(folder_id)).await;
    assert_eq!(resp.status(), 200, "cualquier miembro del grupo debería poder agregar un recurso a la carpeta");

    // Eve (ajena al grupo) no puede.
    let recurso_eve = crear_recurso(&entorno, sesion_eve).await;
    let resp = mover_recurso(&entorno, sesion_eve, recurso_eve, Some(folder_id)).await;
    assert_eq!(resp.status(), 403, "alguien fuera del grupo no debería poder agregar nada a su carpeta");

    // Mover no comparte automáticamente: Dave no puede leer el secreto del recurso de Carol todavía.
    let resp = entorno
        .cliente
        .get(format!("{}/resources/{recurso_carol}/secret", entorno.base))
        .bearer_auth(sesion_dave)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "agregar a la carpeta nunca comparte el recurso en sí, sigue siendo un paso aparte");
}

#[tokio::test]
async fn borrar_recurso_en_carpeta_de_grupo_exige_admin_de_ese_grupo_o_de_organizacion() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "gc-borrar-admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    let dave = common::registrar(&entorno, "gc-borrar-dave@test.ellkan").await; // admin del grupo
    let carol = common::registrar(&entorno, "gc-borrar-carol@test.ellkan").await; // dueña individual del recurso
    let sesion_dave = common::login(&entorno, &dave).await;
    let sesion_carol = common::login(&entorno, &carol).await;

    let g1 = crear_grupo(&entorno, sesion_admin, "G-borrar").await;
    agregar_miembro(&entorno, sesion_admin, g1, dave.user_id, true).await;
    agregar_miembro(&entorno, sesion_admin, g1, carol.user_id, false).await;

    let folder_id = crear_carpeta_ok(&entorno, sesion_dave, None).await;
    let resp = entorno
        .cliente
        .post(format!("{}/folders/{folder_id}/share", entorno.base))
        .bearer_auth(sesion_dave)
        .json(&json!({
            "grantee_type": "group",
            "grantee_id": g1,
            "level": "read",
            "member_envelopes": [
                { "user_id": dave.user_id, "name_ciphertext_b64": "eA==", "name_nonce_b64": "eA==" },
                { "user_id": carol.user_id, "name_ciphertext_b64": "eA==", "name_nonce_b64": "eA==" },
            ],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let recurso = crear_recurso(&entorno, sesion_carol).await;
    let resp = mover_recurso(&entorno, sesion_carol, recurso, Some(folder_id)).await;
    assert_eq!(resp.status(), 200);

    // Carol es la dueña individual (owner) del recurso, pero está en una
    // carpeta de grupo — ni siquiera ella puede borrarlo.
    let resp = entorno
        .cliente
        .delete(format!("{}/resources/{recurso}", entorno.base))
        .bearer_auth(sesion_carol)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "el owner individual no alcanza para borrar un recurso en una carpeta de grupo");

    // Dave (admin del grupo dueño de la carpeta) sí puede.
    let resp = entorno
        .cliente
        .delete(format!("{}/resources/{recurso}", entorno.base))
        .bearer_auth(sesion_dave)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "el admin del grupo dueño de la carpeta debería poder borrar");

    // Confirmar que ya no aparece listado.
    let resp = entorno
        .cliente
        .get(format!("{}/resources", entorno.base))
        .bearer_auth(sesion_carol)
        .send()
        .await
        .unwrap();
    let listado: Value = resp.json().await.unwrap();
    assert!(listado.as_array().unwrap().iter().all(|r| r["id"] != json!(recurso)), "el recurso borrado no debería seguir listado");
}

#[tokio::test]
async fn owner_borra_su_propio_recurso_fuera_de_una_carpeta_de_grupo() {
    let entorno = common::levantar().await;
    let alice = common::registrar(&entorno, "gc-borrar-personal@test.ellkan").await;
    let sesion_alice = common::login(&entorno, &alice).await;

    let recurso = crear_recurso(&entorno, sesion_alice).await;
    let resp = entorno
        .cliente
        .delete(format!("{}/resources/{recurso}", entorno.base))
        .bearer_auth(sesion_alice)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "el owner de un recurso 100% personal debería poder borrarlo");
}

#[tokio::test]
async fn incluir_subcarpetas_trae_tambien_los_recursos_de_las_subcarpetas() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "gc-subcarpetas-admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    let dave = common::registrar(&entorno, "gc-subcarpetas-dave@test.ellkan").await;
    let sesion_dave = common::login(&entorno, &dave).await;
    let g1 = crear_grupo(&entorno, sesion_admin, "G-subcarpetas").await;
    agregar_miembro(&entorno, sesion_admin, g1, dave.user_id, true).await;

    let carpeta_a = crear_carpeta_ok(&entorno, sesion_dave, None).await;
    let carpeta_b = crear_carpeta_ok(&entorno, sesion_dave, Some(carpeta_a)).await;

    let recurso_a = crear_recurso(&entorno, sesion_dave).await;
    mover_recurso(&entorno, sesion_dave, recurso_a, Some(carpeta_a)).await;
    let recurso_b = crear_recurso(&entorno, sesion_dave).await;
    mover_recurso(&entorno, sesion_dave, recurso_b, Some(carpeta_b)).await;

    let resp = entorno
        .cliente
        .get(format!("{}/resources?folder_id={carpeta_a}", entorno.base))
        .bearer_auth(sesion_dave)
        .send()
        .await
        .unwrap();
    let listado: Value = resp.json().await.unwrap();
    let ids: Vec<String> = listado.as_array().unwrap().iter().map(|r| r["id"].as_str().unwrap().to_string()).collect();
    assert!(ids.contains(&recurso_a.to_string()));
    assert!(!ids.contains(&recurso_b.to_string()), "sin incluir_subcarpetas, el filtro es exacto");

    let resp = entorno
        .cliente
        .get(format!("{}/resources?folder_id={carpeta_a}&incluir_subcarpetas=true", entorno.base))
        .bearer_auth(sesion_dave)
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let texto = resp.text().await.unwrap();
    assert_eq!(status, 200, "cuerpo: {texto}");
    let listado: Value = serde_json::from_str(&texto).unwrap();
    let ids: Vec<String> = listado.as_array().unwrap().iter().map(|r| r["id"].as_str().unwrap().to_string()).collect();
    assert!(ids.contains(&recurso_a.to_string()));
    assert!(ids.contains(&recurso_b.to_string()), "con incluir_subcarpetas, debería traer también lo de la subcarpeta");
}
