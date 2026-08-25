// Autor: Athan Espinoza

//! F-26: External Secure Share. El servidor nunca ve la clave de
//! descifrado (vive sólo en el fragmento de la URL, cosa que estos tests no
//! pueden ni necesitan reproducir vía HTTP) — lo que sí se verifica acá es
//! el contrato del servidor: sólo mueve bytes opacos, `GET /{id}` es el
//! único endpoint sin sesión de la API, quema al alcanzar `max_views` o al
//! expirar (con borrado efectivo de `ciphertext`, no sólo un flag), y la
//! política organizacional (F-20) gobierna enable/max-expiration/passphrase
//! obligatoria.

mod common;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::json;

fn ciphertext_de_prueba() -> String {
    B64.encode(b"contenido cifrado de prueba, el servidor nunca lo interpreta")
}

#[tokio::test]
async fn crear_y_leer_un_share_sin_sesion_funciona() {
    let entorno = common::levantar().await;
    let user = common::registrar(&entorno, "creador@test.ellkan").await;
    let sesion = common::login(&entorno, &user).await;

    let resp = entorno
        .cliente
        .post(format!("{}/external-shares", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({
            "ciphertext_b64": ciphertext_de_prueba(),
            "password_protected": false,
            "max_views": 2,
            "expires_in_hours": 72,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cuerpo: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["max_views"], 2);
    let id = cuerpo["id"].as_str().unwrap();

    // GET sin ningún header de auth — es el único endpoint público de la API.
    let resp = entorno.cliente.get(format!("{}/external-shares/{id}", entorno.base)).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    let cuerpo: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["ciphertext_b64"], ciphertext_de_prueba());
    assert_eq!(cuerpo["password_protected"], false);
}

#[tokio::test]
async fn max_views_uno_hace_inaccesible_el_segundo_intento() {
    let entorno = common::levantar().await;
    let user = common::registrar(&entorno, "quemar@test.ellkan").await;
    let sesion = common::login(&entorno, &user).await;

    let resp = entorno
        .cliente
        .post(format!("{}/external-shares", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({ "ciphertext_b64": ciphertext_de_prueba(), "max_views": 1, "expires_in_hours": 72 }))
        .send()
        .await
        .unwrap();
    let cuerpo: serde_json::Value = resp.json().await.unwrap();
    let id = cuerpo["id"].as_str().unwrap();

    let primero = entorno.cliente.get(format!("{}/external-shares/{id}", entorno.base)).send().await.unwrap();
    assert_eq!(primero.status(), 200, "la primera vista debe poder leer el contenido");

    let segundo = entorno.cliente.get(format!("{}/external-shares/{id}", entorno.base)).send().await.unwrap();
    assert_eq!(segundo.status(), 404, "quemado tras max_views=1, el segundo intento debe ser inaccesible aun con el id correcto");

    // Borrado efectivo, no sólo un flag: el ciphertext ya no está en la fila.
    let ciphertext_en_db: (Option<Vec<u8>>,) =
        sqlx::query_as("select ciphertext from external_shares where id = $1")
            .bind(id.parse::<uuid::Uuid>().unwrap())
            .fetch_one(&entorno.pool)
            .await
            .unwrap();
    assert!(ciphertext_en_db.0.is_none(), "el ciphertext debe pisarse con NULL al quemarse, no sólo marcarse inactivo");
}

#[tokio::test]
async fn revocar_lo_hace_inaccesible_y_solo_el_creador_puede() {
    let entorno = common::levantar().await;
    let creador = common::registrar(&entorno, "creador2@test.ellkan").await;
    let sesion_creador = common::login(&entorno, &creador).await;
    let otro = common::registrar(&entorno, "otro@test.ellkan").await;
    let sesion_otro = common::login(&entorno, &otro).await;

    let resp = entorno
        .cliente
        .post(format!("{}/external-shares", entorno.base))
        .bearer_auth(sesion_creador)
        .json(&json!({ "ciphertext_b64": ciphertext_de_prueba(), "expires_in_hours": 72 }))
        .send()
        .await
        .unwrap();
    let cuerpo: serde_json::Value = resp.json().await.unwrap();
    let id = cuerpo["id"].as_str().unwrap();

    // Otro usuario no puede revocar el share de alguien más.
    let resp = entorno
        .cliente
        .delete(format!("{}/external-shares/{id}", entorno.base))
        .bearer_auth(sesion_otro)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    let resp = entorno
        .cliente
        .delete(format!("{}/external-shares/{id}", entorno.base))
        .bearer_auth(sesion_creador)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let resp = entorno.cliente.get(format!("{}/external-shares/{id}", entorno.base)).send().await.unwrap();
    assert_eq!(resp.status(), 404, "revocado, inaccesible aunque el destinatario tenga la URL completa");
}

#[tokio::test]
async fn un_share_expirado_por_tiempo_es_inaccesible_antes_de_intentar_descifrar_nada() {
    let entorno = common::levantar().await;
    let user = common::registrar(&entorno, "expira@test.ellkan").await;
    let sesion = common::login(&entorno, &user).await;

    let resp = entorno
        .cliente
        .post(format!("{}/external-shares", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({ "ciphertext_b64": ciphertext_de_prueba(), "expires_in_hours": 1 }))
        .send()
        .await
        .unwrap();
    let cuerpo: serde_json::Value = resp.json().await.unwrap();
    let id = cuerpo["id"].as_str().unwrap();

    sqlx::query("update external_shares set expires_at = now() - interval '1 hour' where id = $1")
        .bind(id.parse::<uuid::Uuid>().unwrap())
        .execute(&entorno.pool)
        .await
        .unwrap();

    let resp = entorno.cliente.get(format!("{}/external-shares/{id}", entorno.base)).send().await.unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn get_de_un_id_inexistente_da_404_igual_que_uno_quemado() {
    let entorno = common::levantar().await;
    let resp = entorno
        .cliente
        .get(format!("{}/external-shares/{}", entorno.base, uuid::Uuid::new_v4()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn no_admin_no_puede_leer_ni_cambiar_la_politica() {
    let entorno = common::levantar().await;
    let user = common::registrar(&entorno, "sinadmin@test.ellkan").await;
    let sesion = common::login(&entorno, &user).await;

    let resp = entorno
        .cliente
        .get(format!("{}/admin/external-share-policy", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn defaults_de_fabrica_coinciden_con_la_spec() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion = common::login(&entorno, &admin).await;

    let resp = entorno
        .cliente
        .get(format!("{}/admin/external-share-policy", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    let cuerpo: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["enabled"], true);
    assert_eq!(cuerpo["max_expiration_hours"], 168);
    assert_eq!(cuerpo["require_password"], false);
}

#[tokio::test]
async fn politica_deshabilitada_bloquea_la_creacion() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admindeshab@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    let resp = entorno
        .cliente
        .put(format!("{}/admin/external-share-policy", entorno.base))
        .bearer_auth(sesion_admin)
        .json(&json!({ "enabled": false, "max_expiration_hours": 168, "require_password": false, "allow_link": true, "allow_file": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let user = common::registrar(&entorno, "creadordeshab@test.ellkan").await;
    let sesion = common::login(&entorno, &user).await;
    let resp = entorno
        .cliente
        .post(format!("{}/external-shares", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({ "ciphertext_b64": ciphertext_de_prueba(), "expires_in_hours": 72 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn politica_de_passphrase_obligatoria_rechaza_un_share_sin_password_protected() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "adminpw@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    let resp = entorno
        .cliente
        .put(format!("{}/admin/external-share-policy", entorno.base))
        .bearer_auth(sesion_admin)
        .json(&json!({ "enabled": true, "max_expiration_hours": 168, "require_password": true, "allow_link": true, "allow_file": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let user = common::registrar(&entorno, "creadorpw@test.ellkan").await;
    let sesion = common::login(&entorno, &user).await;

    let resp = entorno
        .cliente
        .post(format!("{}/external-shares", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({ "ciphertext_b64": ciphertext_de_prueba(), "password_protected": false, "expires_in_hours": 72 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "la política exige la capa de passphrase");

    let resp = entorno
        .cliente
        .post(format!("{}/external-shares", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({
            "ciphertext_b64": ciphertext_de_prueba(),
            "password_protected": true,
            "password_salt_b64": B64.encode(b"un-salt-cualquiera"),
            "expires_in_hours": 72,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "con password_protected=true y salt, la política ya está satisfecha");
}

#[tokio::test]
async fn expires_in_hours_por_encima_del_maximo_de_politica_se_rechaza() {
    let entorno = common::levantar().await;
    let user = common::registrar(&entorno, "excede@test.ellkan").await;
    let sesion = common::login(&entorno, &user).await;

    let resp = entorno
        .cliente
        .post(format!("{}/external-shares", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({ "ciphertext_b64": ciphertext_de_prueba(), "expires_in_hours": 999_999 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "999_999 horas supera el default de política (168)");
}

/// `allow_link=false` (distinto de `enabled=false`): el archivo .7z sigue
/// permitido (no pasa por acá, nunca toca el servidor), pero crear un link
/// se rechaza igual que si toda la política estuviera apagada.
#[tokio::test]
async fn allow_link_en_false_bloquea_la_creacion_de_link() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "adminsololink@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    let resp = entorno
        .cliente
        .put(format!("{}/admin/external-share-policy", entorno.base))
        .bearer_auth(sesion_admin)
        .json(&json!({ "enabled": true, "max_expiration_hours": 168, "require_password": false, "allow_link": false, "allow_file": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let user = common::registrar(&entorno, "creadorsololink@test.ellkan").await;
    let sesion = common::login(&entorno, &user).await;
    let resp = entorno
        .cliente
        .post(format!("{}/external-shares", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({ "ciphertext_b64": ciphertext_de_prueba(), "expires_in_hours": 72 }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

/// `allow_link=false` y `allow_file=false` a la vez no es un estado válido
/// de la política (no quedaría ninguna forma de compartir externo) — el
/// backend lo rechaza, no lo acepta en silencio.
#[tokio::test]
async fn allow_link_y_allow_file_ambos_en_false_se_rechaza() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "adminningunmetodo@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    let resp = entorno
        .cliente
        .put(format!("{}/admin/external-share-policy", entorno.base))
        .bearer_auth(sesion_admin)
        .json(&json!({ "enabled": true, "max_expiration_hours": 168, "require_password": false, "allow_link": false, "allow_file": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

/// `GET /external-share-policy` (no-admin) — el Vault la necesita para
/// decidir qué mostrar, sin requerir rol de admin.
#[tokio::test]
async fn politica_no_admin_es_legible_por_cualquier_usuario_autenticado() {
    let entorno = common::levantar().await;
    let user = common::registrar(&entorno, "usuarionoadmin@test.ellkan").await;
    let sesion = common::login(&entorno, &user).await;

    let resp = entorno
        .cliente
        .get(format!("{}/external-share-policy", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let cuerpo: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["allow_link"], true);
    assert_eq!(cuerpo["allow_file"], true);
}
