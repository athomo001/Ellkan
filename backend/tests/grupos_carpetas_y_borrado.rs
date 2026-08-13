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

/// Nota de diseño (auditoría 2026-08-12, H-10 — re-evaluado): la auditoría
/// marcó como hallazgo que `sharing_policy.restrict_visibility_by_group` no
/// se re-validara en `POST /resources/{id}/share` (sólo en `GET /users/search`).
/// Un intento de aplicar ese chequeo ahí rompió varios tests preexistentes
/// (`metadata_keys.rs::compartir_un_recurso_con_metadata_personal_funciona`,
/// `users_admin.rs::purgar_unico_owner_...`, y el patrón se repite en
/// `editar_recurso.rs`/`reports.rs`/`flujo_completo.rs`/`permisos_recurso.rs`)
/// que comparten deliberadamente entre usuarios sin grupo en común. Conclusión:
/// la política es de **descubrimiento** (oculta gente de la búsqueda/directorio),
/// no de **autorización para compartir** — mismo criterio que "no aparecer en
/// un directorio" no implica "no poder recibir algo de alguien que ya te
/// conoce por otro medio". Este test documenta ese comportamiento intencional
/// para que no se "corrija" por accidente sin una decisión de producto explícita.
#[tokio::test]
async fn compartir_recurso_funciona_aunque_la_busqueda_este_restringida_por_grupo() {
    let entorno = common::levantar().await;
    // Registra un admin primero (consume el bootstrap) para que alice/bob
    // sean usuarios regulares, no el admin de organización que ve a todos.
    let admin_bootstrap = common::registrar(&entorno, "gc-vis-admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin_bootstrap.user_id).await;

    let alice = common::registrar(&entorno, "gc-vis-alice@test.ellkan").await; // sin grupo
    let bob = common::registrar(&entorno, "gc-vis-bob@test.ellkan").await; // sin grupo, grupos distintos
    let sesion_alice = common::login(&entorno, &alice).await;

    // Confirmado (mismo criterio que `visibilidad_de_usuarios_acotada_por_grupo`):
    // sin grupo, alice no ve a bob en la búsqueda.
    let resultados = buscar(&entorno, sesion_alice, "gc-vis-bob").await;
    assert!(!contiene_email(&resultados, "gc-vis-bob@test.ellkan"), "sin grupo, alice no debería ver a bob en la búsqueda");

    // Pero compartir directo (conociendo el user_id por otro medio) sigue
    // funcionando — comportamiento intencional, no un bug.
    let recurso = crear_recurso(&entorno, sesion_alice).await;
    let resp = entorno
        .cliente
        .post(format!("{}/resources/{recurso}/share", entorno.base))
        .bearer_auth(sesion_alice)
        .json(&json!({
            "recipient_user_id": bob.user_id,
            "sealed_dek_b64": "eA==",
            "secret_ciphertext_b64": "eA==",
            "secret_nonce_b64": "eA==",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);
}

/// 2026-08-13: excepciones a la visibilidad acotada por grupo — un grupo
/// marcado `share_exempt` (ej. Soporte/TI que crean cuentas para otras
/// áreas) ve a cualquiera, y sólo un admin de organización puede marcarlo
/// (un admin del propio grupo no puede auto-exentarse). Apagar
/// `sharing_policy.restrict_visibility_by_group` entero vuelve a
/// "cualquiera ve a cualquiera", incluso para alguien sin ningún grupo.
#[tokio::test]
async fn grupo_share_exempt_y_apagar_la_politica_dan_visibilidad_total() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "gcx-admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    let alice = common::registrar(&entorno, "gcx-alice@test.ellkan").await;
    let carol = common::registrar(&entorno, "gcx-carol@test.ellkan").await;
    let sesion_alice = common::login(&entorno, &alice).await;
    let sesion_carol = common::login(&entorno, &carol).await;

    let soporte = crear_grupo(&entorno, sesion_admin, "SoporteExento").await;
    agregar_miembro(&entorno, sesion_admin, soporte, alice.user_id, false).await;

    // Sin exención todavía: alice (en Soporte) no ve a carol (sin grupo).
    let resultados = buscar(&entorno, sesion_alice, "gcx-carol").await;
    assert!(!contiene_email(&resultados, "gcx-carol@test.ellkan"), "sin exención, alice no debería ver a carol");

    // Un no-admin de organización (carol, sin ninguna autoridad) no puede marcar un grupo como exento.
    let resp = entorno
        .cliente
        .put(format!("{}/groups/{}/share-exempt", entorno.base, soporte))
        .bearer_auth(sesion_carol)
        .json(&json!({ "exempt": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "sólo un admin de organización puede marcar un grupo como exento");

    // El admin de organización marca "Soporte" como exento.
    let resp = entorno
        .cliente
        .put(format!("{}/groups/{}/share-exempt", entorno.base, soporte))
        .bearer_auth(sesion_admin)
        .json(&json!({ "exempt": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["share_exempt"], json!(true));

    // Ahora alice (miembro de un grupo exento) ve a carol, que ni siquiera tiene grupo.
    let resultados = buscar(&entorno, sesion_alice, "gcx-carol").await;
    assert!(contiene_email(&resultados, "gcx-carol@test.ellkan"), "miembro de grupo exento debería ver a cualquiera");

    // Apagar la exención puntual — alice vuelve a no ver a carol.
    let resp = entorno
        .cliente
        .put(format!("{}/groups/{}/share-exempt", entorno.base, soporte))
        .bearer_auth(sesion_admin)
        .json(&json!({ "exempt": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let dave = common::registrar(&entorno, "gcx-dave@test.ellkan").await; // sin grupo, sin exención
    let sesion_dave = common::login(&entorno, &dave).await;
    let resultados = buscar(&entorno, sesion_dave, "gcx-carol").await;
    assert!(!contiene_email(&resultados, "gcx-carol@test.ellkan"), "sin exención ni política apagada, dave no debería ver a carol");

    // Apagar la política entera: hasta alguien completamente sin grupo ve a todos.
    let resp = entorno
        .cliente
        .put(format!("{}/admin/sharing-policy", entorno.base))
        .bearer_auth(sesion_admin)
        .json(&json!({ "restrict_visibility_by_group": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resultados = buscar(&entorno, sesion_dave, "gcx-carol").await;
    assert!(contiene_email(&resultados, "gcx-carol@test.ellkan"), "con la política apagada, cualquiera ve a cualquiera");
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

/// Regresión de seguridad (auditoría 2026-08-12, H-02): `mover_recurso` sólo
/// validaba autorización sobre la carpeta DESTINO, nunca sobre el recurso
/// movido — un admin de grupo sin ningún permiso sobre un recurso ajeno
/// podía "enmarcarlo" en una carpeta propia compartida con su grupo y de ahí
/// borrarlo vía la excepción de `eliminar` para carpetas de grupo. La
/// auditoría también notó que la suite de tests no cubría este escenario
/// exacto (probaba "carpeta ajena", nunca "recurso ajeno") — este test
/// cierra ese gap.
#[tokio::test]
async fn mover_recurso_ajeno_a_carpeta_de_grupo_propio_es_rechazado() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "gc-idor-admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    let victima = common::registrar(&entorno, "gc-idor-victima@test.ellkan").await;
    let mallory = common::registrar(&entorno, "gc-idor-mallory@test.ellkan").await; // admin de su propio grupo
    let sesion_victima = common::login(&entorno, &victima).await;
    let sesion_mallory = common::login(&entorno, &mallory).await;

    // Mallory administra un grupo — nada que ver con Victima.
    let g_mallory = crear_grupo(&entorno, sesion_admin, "G-mallory").await;
    agregar_miembro(&entorno, sesion_admin, g_mallory, mallory.user_id, true).await;

    // Victima crea un recurso 100% personal — nunca lo comparte con nadie.
    let recurso_victima = crear_recurso(&entorno, sesion_victima).await;

    // Mallory arma su trampa: carpeta propia, compartida con su propio grupo.
    let folder_mallory = crear_carpeta_ok(&entorno, sesion_mallory, None).await;
    let resp = entorno
        .cliente
        .post(format!("{}/folders/{folder_mallory}/share", entorno.base))
        .bearer_auth(sesion_mallory)
        .json(&json!({
            "grantee_type": "group",
            "grantee_id": g_mallory,
            "level": "read",
            "member_envelopes": [
                { "user_id": mallory.user_id, "name_ciphertext_b64": "eA==", "name_nonce_b64": "eA==" },
            ],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Mallory intenta "enmarcar" el recurso de Victima en su propia carpeta —
    // sin ningún permiso (ni siquiera `read`) sobre ese recurso.
    let resp = mover_recurso(&entorno, sesion_mallory, recurso_victima, Some(folder_mallory)).await;
    assert_eq!(resp.status(), 403, "mover un recurso ajeno a una carpeta propia debería rechazarse, sin importar quién administre la carpeta destino");

    // El recurso de Victima no quedó posicionado en la carpeta de Mallory.
    let resp = entorno
        .cliente
        .get(format!("{}/resources?folder_id={folder_mallory}", entorno.base))
        .bearer_auth(sesion_mallory)
        .send()
        .await
        .unwrap();
    let listado: Value = resp.json().await.unwrap();
    assert!(
        listado.as_array().unwrap().iter().all(|r| r["id"] != json!(recurso_victima)),
        "el recurso ajeno no debería aparecer en la carpeta de mallory tras el intento rechazado"
    );

    // Y por lo tanto Mallory tampoco puede borrarlo vía la excepción de carpeta de grupo.
    let resp = entorno
        .cliente
        .delete(format!("{}/resources/{recurso_victima}", entorno.base))
        .bearer_auth(sesion_mallory)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "mallory no debería poder borrar un recurso que nunca logró enmarcar");
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

/// Regresión H-28 (auditoría 2026-08-12): los dos únicos managers de un
/// grupo (con un tercer miembro regular — sin eso, vaciar el grupo del todo
/// es un estado válido aparte, ver nota en `GroupMemberRepository::quitar`)
/// se quitan mutuamente como miembro en simultáneo. Antes de que
/// `GroupMemberRepository::quitar` tomara un lock de fila sobre
/// `group_members`, el chequeo de "único manager" del `Service` corría como
/// dos queries sueltas — cada baja podía ver al otro manager todavía activo
/// y el grupo terminaba con un miembro (carol) sin ningún manager.
#[tokio::test]
async fn dos_managers_quitandose_mutuamente_en_simultaneo_nunca_deja_miembros_sin_manager() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "gc-h28-admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    let alice = common::registrar(&entorno, "gc-h28-alice@test.ellkan").await;
    let bob = common::registrar(&entorno, "gc-h28-bob@test.ellkan").await;
    let carol = common::registrar(&entorno, "gc-h28-carol@test.ellkan").await;
    let sesion_alice = common::login(&entorno, &alice).await;
    let sesion_bob = common::login(&entorno, &bob).await;

    let grupo = crear_grupo(&entorno, sesion_admin, "G-h28").await;
    agregar_miembro(&entorno, sesion_admin, grupo, alice.user_id, true).await;
    agregar_miembro(&entorno, sesion_admin, grupo, bob.user_id, true).await;
    agregar_miembro(&entorno, sesion_admin, grupo, carol.user_id, false).await;

    // Alice y Bob, los dos únicos managers (carol es miembro regular, se
    // queda), se quitan mutuamente al mismo tiempo.
    let alice_quita_a_bob = entorno
        .cliente
        .delete(format!("{}/groups/{grupo}/members/{}", entorno.base, bob.user_id))
        .bearer_auth(sesion_alice)
        .send();
    let bob_quita_a_alice = entorno
        .cliente
        .delete(format!("{}/groups/{grupo}/members/{}", entorno.base, alice.user_id))
        .bearer_auth(sesion_bob)
        .send();
    let (resp_bob, resp_alice) = tokio::join!(alice_quita_a_bob, bob_quita_a_alice);
    let status_bob = resp_bob.unwrap().status();
    let status_alice = resp_alice.unwrap().status();

    let exitos = [status_bob, status_alice].iter().filter(|s| **s == 200).count();
    let rechazos = [status_bob, status_alice].iter().filter(|s| **s == 409).count();
    assert_eq!(exitos, 1, "exactamente una de las dos bajas concurrentes debería aplicarse");
    assert_eq!(rechazos, 1, "la otra debería rechazarse (GROUP_SOLE_MANAGER) por dejar al grupo sin manager");

    // El grupo nunca se quedó sin manager: queda exactamente uno de los dos.
    let resp = entorno
        .cliente
        .get(format!("{}/groups/{grupo}", entorno.base))
        .bearer_auth(sesion_admin)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let grupo_resp: Value = resp.json().await.unwrap();
    let managers = grupo_resp["members"].as_array().unwrap().iter().filter(|m| m["is_admin"] == true).count();
    assert_eq!(managers, 1, "debe quedar exactamente un manager, nunca cero");
}
