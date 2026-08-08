// Autor: Athan Espinoza

//! F-12: criterios de aceptación literales — manager sin admin de org puede
//! gestionar su grupo, admin de org puede gestionar cualquiera, único
//! manager no se puede quitar/degradar, agregar miembro a grupo con acceso
//! a N recursos exige N envelopes, subgrupos sin herencia de acceso, grupo
//! raíz sin admin falla, ciclos fallan, borrar con subgrupos falla, borrar
//! único Owner falla.

mod common;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ellkan_crypto::aead;
use ellkan_crypto::sellado;
use secrecy::{ExposeSecret, SecretBox};
use serde_json::{json, Value};
use uuid::Uuid;

/// Comparte `resource_id` directamente con el grupo (`grantee_type='group'`)
/// vía SQL — F-11 (compartir con grupos vía endpoint) no es parte de F-12,
/// así que el test arma la precondición "el grupo ya tiene acceso" a mano,
/// igual criterio que `common::promover_admin`.
async fn otorgar_permiso_a_grupo(pool: &sqlx::PgPool, resource_id: Uuid, group_id: Uuid, nivel: &str) {
    sqlx::query(
        "insert into permissions (subject_type, subject_id, grantee_type, grantee_id, level)
         values ('resource', $1, 'group', $2, $3)",
    )
    .bind(resource_id)
    .bind(group_id)
    .bind(nivel)
    .execute(pool)
    .await
    .unwrap();
}

struct RecursoDePrueba {
    id: Uuid,
    dek: SecretBox<[u8; 32]>,
}

async fn crear_recurso_compartido_con_grupo(
    entorno: &common::Entorno,
    sesion_owner: Uuid,
    owner: &common::Usuario,
    group_id: Uuid,
) -> RecursoDePrueba {
    let dek_bytes: [u8; 32] = ellkan_crypto::aleatoriedad::bytes_aleatorios();
    let dek_secreta = SecretBox::new(Box::new(dek_bytes));
    let resource_id = Uuid::now_v7();
    let mut aad = Vec::new();
    aad.extend_from_slice(resource_id.as_bytes());
    aad.extend_from_slice(owner.user_id.as_bytes());
    let metadata_env = aead::cifrar(&dek_secreta, b"{}", &aad).unwrap();
    let secreto_env = aead::cifrar(&dek_secreta, b"contenido-secreto", &aad).unwrap();
    let sealed_dek = sellado::sellar_dek(owner.x25519.publica(), &dek_secreta);

    let resp = entorno
        .cliente
        .post(format!("{}/resources", entorno.base))
        .bearer_auth(sesion_owner)
        .json(&json!({
            "id": resource_id,
            "resource_type_slug": "login-password",
            "metadata_ciphertext_b64": B64.encode(&metadata_env.ciphertext),
            "metadata_nonce_b64": B64.encode(metadata_env.nonce),
            "sealed_dek_b64": B64.encode(&sealed_dek),
            "secret_ciphertext_b64": B64.encode(&secreto_env.ciphertext),
            "secret_nonce_b64": B64.encode(secreto_env.nonce),
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    otorgar_permiso_a_grupo(&entorno.pool, resource_id, group_id, "read").await;

    RecursoDePrueba { id: resource_id, dek: dek_secreta }
}

async fn crear_grupo_raiz(entorno: &common::Entorno, sesion_admin: Uuid, name: &str) -> Uuid {
    let id = Uuid::now_v7();
    let resp = entorno
        .cliente
        .post(format!("{}/groups", entorno.base))
        .bearer_auth(sesion_admin)
        .json(&json!({ "id": id, "name": name }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "crear grupo raíz debería funcionar para un admin");
    id
}

#[tokio::test]
async fn crear_grupo_raiz_sin_admin_de_org_falla() {
    let entorno = common::levantar().await;
    let user = common::registrar(&entorno, "no-admin-grp@test.ellkan").await;
    let sesion = common::login(&entorno, &user).await;

    let resp = entorno
        .cliente
        .post(format!("{}/groups", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({ "id": Uuid::now_v7(), "name": "TI" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn manager_sin_admin_de_org_gestiona_su_grupo_y_promueve_otro_manager() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin-grp-1@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    let manager = common::registrar(&entorno, "manager-grp-1@test.ellkan").await;
    let sesion_manager = common::login(&entorno, &manager).await;
    let otro = common::registrar(&entorno, "otro-grp-1@test.ellkan").await;
    common::login(&entorno, &otro).await;

    let grupo_id = crear_grupo_raiz(&entorno, sesion_admin, "TI").await;

    // El admin agrega al manager como manager del grupo.
    let resp = entorno
        .cliente
        .post(format!("{}/groups/{grupo_id}/members/{}", entorno.base, manager.user_id))
        .bearer_auth(sesion_admin)
        .json(&json!({ "is_admin": true, "envelopes": [] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // El manager (sin ser admin de organización) agrega a `otro` como miembro regular.
    let resp = entorno
        .cliente
        .post(format!("{}/groups/{grupo_id}/members/{}", entorno.base, otro.user_id))
        .bearer_auth(sesion_manager)
        .json(&json!({ "is_admin": false, "envelopes": [] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "un manager de grupo (sin admin de org) puede agregar miembros");

    // Y promueve a `otro` a manager también.
    let resp = entorno
        .cliente
        .put(format!("{}/groups/{grupo_id}/members/{}", entorno.base, otro.user_id))
        .bearer_auth(sesion_manager)
        .json(&json!({ "is_admin": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "un manager puede promover a otro manager");
}

#[tokio::test]
async fn unico_manager_no_se_puede_quitar_ni_degradar() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin-grp-2@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    let manager = common::registrar(&entorno, "manager-grp-2@test.ellkan").await;
    common::login(&entorno, &manager).await;

    let grupo_id = crear_grupo_raiz(&entorno, sesion_admin, "Solo").await;
    let resp = entorno
        .cliente
        .post(format!("{}/groups/{grupo_id}/members/{}", entorno.base, manager.user_id))
        .bearer_auth(sesion_admin)
        .json(&json!({ "is_admin": true, "envelopes": [] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Degradar al único manager falla.
    let resp = entorno
        .cliente
        .put(format!("{}/groups/{grupo_id}/members/{}", entorno.base, manager.user_id))
        .bearer_auth(sesion_admin)
        .json(&json!({ "is_admin": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["error"]["code"], "GROUP_SOLE_MANAGER");

    // Agregar a un segundo miembro (no manager) y luego quitar al único
    // manager, dejando el grupo no-vacío, también falla.
    let otro = common::registrar(&entorno, "otro-grp-2@test.ellkan").await;
    common::login(&entorno, &otro).await;
    entorno
        .cliente
        .post(format!("{}/groups/{grupo_id}/members/{}", entorno.base, otro.user_id))
        .bearer_auth(sesion_admin)
        .json(&json!({ "is_admin": false, "envelopes": [] }))
        .send()
        .await
        .unwrap();

    let resp = entorno
        .cliente
        .delete(format!("{}/groups/{grupo_id}/members/{}", entorno.base, manager.user_id))
        .bearer_auth(sesion_admin)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409, "quitar al único manager de un grupo que queda no-vacío debe fallar");
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["error"]["code"], "GROUP_SOLE_MANAGER");
}

#[tokio::test]
async fn agregar_miembro_a_grupo_con_recursos_exige_envelopes_y_da_acceso_verificable() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin-grp-3@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;
    let nuevo = common::registrar(&entorno, "nuevo-grp-3@test.ellkan").await;
    let sesion_nuevo = common::login(&entorno, &nuevo).await;

    let grupo_id = crear_grupo_raiz(&entorno, sesion_admin, "ConRecursos").await;
    let recurso = crear_recurso_compartido_con_grupo(&entorno, sesion_admin, &admin, grupo_id).await;

    // Sin envelopes -> falla (el grupo ya tiene 1 recurso compartido).
    let resp = entorno
        .cliente
        .post(format!("{}/groups/{grupo_id}/members/{}", entorno.base, nuevo.user_id))
        .bearer_auth(sesion_admin)
        .json(&json!({ "is_admin": false, "envelopes": [] }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "agregar sin cubrir los envelopes del recurso ya compartido debe fallar");

    // Con el envelope correcto -> funciona.
    let sealed_dek_nuevo = sellado::sellar_dek(nuevo.x25519.publica(), &recurso.dek);
    let mut aad = Vec::new();
    aad.extend_from_slice(recurso.id.as_bytes());
    aad.extend_from_slice(admin.user_id.as_bytes());
    let secreto_env = aead::cifrar(&recurso.dek, b"contenido-secreto", &aad).unwrap();

    let resp = entorno
        .cliente
        .post(format!("{}/groups/{grupo_id}/members/{}", entorno.base, nuevo.user_id))
        .bearer_auth(sesion_admin)
        .json(&json!({
            "is_admin": false,
            "envelopes": [{
                "resource_id": recurso.id,
                "sealed_dek_b64": B64.encode(&sealed_dek_nuevo),
                "secret_ciphertext_b64": B64.encode(&secreto_env.ciphertext),
                "secret_nonce_b64": B64.encode(secreto_env.nonce),
            }],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Acceso verificable de inmediato: `nuevo` puede leer el secreto.
    let resp = entorno
        .cliente
        .get(format!("{}/resources/{}/secret", entorno.base, recurso.id))
        .bearer_auth(sesion_nuevo)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "acceso de lectura vía grupo debe funcionar de inmediato");
    let cuerpo: Value = resp.json().await.unwrap();
    let sealed_dek_recibido = B64.decode(cuerpo["sealed_dek_b64"].as_str().unwrap()).unwrap();
    let dek_de_nuevo = sellado::abrir_dek(nuevo.x25519.privada(), &sealed_dek_recibido).unwrap();
    assert_eq!(dek_de_nuevo.expose_secret(), recurso.dek.expose_secret());
}

/// `GET /groups/{id}/resources` (F-12) — lo que el cliente consulta antes
/// de agregar un miembro nuevo, para saber a qué recursos re-sellar.
#[tokio::test]
async fn recursos_compartidos_del_grupo_refleja_lo_que_ya_tiene_acceso() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin-grp-recursos@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    let grupo_id = crear_grupo_raiz(&entorno, sesion_admin, "ConRecursosListado").await;

    // Sin recursos compartidos todavía -> lista vacía.
    let resp = entorno
        .cliente
        .get(format!("{}/groups/{grupo_id}/resources", entorno.base))
        .bearer_auth(sesion_admin)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let vacio: Value = resp.json().await.unwrap();
    assert_eq!(vacio.as_array().unwrap().len(), 0);

    let recurso = crear_recurso_compartido_con_grupo(&entorno, sesion_admin, &admin, grupo_id).await;

    let resp = entorno
        .cliente
        .get(format!("{}/groups/{grupo_id}/resources", entorno.base))
        .bearer_auth(sesion_admin)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let lista: Value = resp.json().await.unwrap();
    let ids: Vec<String> = lista.as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert_eq!(ids, vec![recurso.id.to_string()]);

    // Un usuario sin autoridad sobre el grupo no puede consultarlo.
    let otro = common::registrar(&entorno, "otro-grp-recursos@test.ellkan").await;
    let sesion_otro = common::login(&entorno, &otro).await;
    let resp = entorno
        .cliente
        .get(format!("{}/groups/{grupo_id}/resources", entorno.base))
        .bearer_auth(sesion_otro)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn subgrupo_sin_herencia_de_acceso() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin-grp-4@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    let gerente = common::registrar(&entorno, "gerente-grp-4@test.ellkan").await;
    let sesion_gerente = common::login(&entorno, &gerente).await;
    let miembro_ti = common::registrar(&entorno, "miembro-ti-grp-4@test.ellkan").await;
    let sesion_miembro_ti = common::login(&entorno, &miembro_ti).await;

    let ti_id = crear_grupo_raiz(&entorno, sesion_admin, "TI").await;
    entorno
        .cliente
        .post(format!("{}/groups/{ti_id}/members/{}", entorno.base, gerente.user_id))
        .bearer_auth(sesion_admin)
        .json(&json!({ "is_admin": true, "envelopes": [] }))
        .send()
        .await
        .unwrap();
    entorno
        .cliente
        .post(format!("{}/groups/{ti_id}/members/{}", entorno.base, miembro_ti.user_id))
        .bearer_auth(sesion_admin)
        .json(&json!({ "is_admin": false, "envelopes": [] }))
        .send()
        .await
        .unwrap();

    // El gerente de TI (sin ningún rol de F-22) crea "TI/Servidores".
    let subgrupo_id = Uuid::now_v7();
    let resp = entorno
        .cliente
        .post(format!("{}/groups", entorno.base))
        .bearer_auth(sesion_gerente)
        .json(&json!({ "id": subgrupo_id, "name": "Servidores", "parent_group_id": ti_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "manager de TI crea subgrupo sin admin de organización");

    let resp = entorno
        .cliente
        .get(format!("{}/groups/{ti_id}/subgroups", entorno.base))
        .bearer_auth(sesion_admin)
        .send()
        .await
        .unwrap();
    let hijos: Value = resp.json().await.unwrap();
    assert_eq!(hijos.as_array().unwrap().len(), 1);
    assert_eq!(hijos[0]["id"], json!(subgrupo_id));

    // Comparte un recurso específicamente con "TI/Servidores".
    let recurso = crear_recurso_compartido_con_grupo(&entorno, sesion_admin, &admin, subgrupo_id).await;

    // `miembro_ti` (de "TI", no de "TI/Servidores") no ve ese recurso.
    let resp = entorno
        .cliente
        .get(format!("{}/resources/{}/secret", entorno.base, recurso.id))
        .bearer_auth(sesion_miembro_ti)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "sin herencia de acceso: miembro de TI no ve recursos de TI/Servidores");
}

#[tokio::test]
async fn reparentar_creando_un_ciclo_falla() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin-grp-5@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    let raiz_id = crear_grupo_raiz(&entorno, sesion_admin, "Raiz").await;
    let hijo_id = Uuid::now_v7();
    entorno
        .cliente
        .post(format!("{}/groups", entorno.base))
        .bearer_auth(sesion_admin)
        .json(&json!({ "id": hijo_id, "name": "Hijo", "parent_group_id": raiz_id }))
        .send()
        .await
        .unwrap();

    // Intentar que "Raiz" pase a ser hijo de su propio hijo -> ciclo.
    let resp = entorno
        .cliente
        .put(format!("{}/groups/{raiz_id}/move", entorno.base))
        .bearer_auth(sesion_admin)
        .json(&json!({ "new_parent_group_id": hijo_id }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["error"]["code"], "GROUP_CYCLE");
}

#[tokio::test]
async fn borrar_grupo_con_subgrupos_falla() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin-grp-6@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    let raiz_id = crear_grupo_raiz(&entorno, sesion_admin, "ConHijos").await;
    entorno
        .cliente
        .post(format!("{}/groups", entorno.base))
        .bearer_auth(sesion_admin)
        .json(&json!({ "id": Uuid::now_v7(), "name": "Hijo", "parent_group_id": raiz_id }))
        .send()
        .await
        .unwrap();

    let resp = entorno
        .cliente
        .delete(format!("{}/groups/{raiz_id}", entorno.base))
        .bearer_auth(sesion_admin)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["error"]["code"], "GROUP_HAS_SUBGROUPS");
}

#[tokio::test]
async fn borrar_grupo_unico_owner_de_un_recurso_falla() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin-grp-7@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;

    let grupo_id = crear_grupo_raiz(&entorno, sesion_admin, "Duenio").await;
    let recurso = crear_recurso_compartido_con_grupo(&entorno, sesion_admin, &admin, grupo_id).await;
    // El helper ya otorgó `read` al grupo — se sube a `owner`, y se retira
    // el `owner` directo que `ResourceService::crear` le dio al creador
    // (`admin`), para simular ownership totalmente transferido al grupo:
    // sin esto el admin seguiría siendo "otro owner" y borrar no fallaría.
    sqlx::query(
        "update permissions set level = 'owner'
         where subject_type = 'resource' and subject_id = $1 and grantee_type = 'group' and grantee_id = $2",
    )
    .bind(recurso.id)
    .bind(grupo_id)
    .execute(&entorno.pool)
    .await
    .unwrap();
    sqlx::query(
        "delete from permissions
         where subject_type = 'resource' and subject_id = $1 and grantee_type = 'user' and grantee_id = $2",
    )
    .bind(recurso.id)
    .bind(admin.user_id)
    .execute(&entorno.pool)
    .await
    .unwrap();

    let resp = entorno
        .cliente
        .delete(format!("{}/groups/{grupo_id}", entorno.base))
        .bearer_auth(sesion_admin)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(cuerpo["error"]["code"], "GROUP_SOLE_OWNER");
}
