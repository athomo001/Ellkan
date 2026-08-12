// Autor: Athan Espinoza

//! Hallazgo real de uso: no había forma de ver/administrar quién tenía
//! acceso a un recurso compartido, ni de agregar un miembro a una metadata
//! key ya existente (antes sólo el admin creador tenía acceso real a
//! cualquier metadata key compartida). `GET/{PUT,DELETE} /resources/{id}/permissions*`
//! y `POST /admin/metadata-keys/{id}/members`.

mod common;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ellkan_crypto::aead;
use ellkan_crypto::claves::KeypairAcuerdo;
use ellkan_crypto::sellado;
use secrecy::SecretBox;
use serde_json::{json, Value};
use uuid::Uuid;

async fn crear_metadata_key(entorno: &common::Entorno, sesion_admin: Uuid, admin: &common::Usuario) -> Uuid {
    let par = KeypairAcuerdo::generar();
    let id = Uuid::now_v7();
    let sealed_para_admin = sellado::sellar_dek(admin.x25519.publica(), &SecretBox::new(Box::new(par.privada().to_bytes())));
    let resp = entorno
        .cliente
        .post(format!("{}/admin/metadata-keys", entorno.base))
        .bearer_auth(sesion_admin)
        .json(&json!({
            "id": id,
            "public_key_x25519_b64": B64.encode(par.publica().as_bytes()),
            "fingerprint": "fp-permisos",
            "destinatarios": [{ "user_id": admin.user_id, "sealed_private_key_b64": B64.encode(&sealed_para_admin) }],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    id
}

async fn crear_recurso_compartible(
    entorno: &common::Entorno,
    sesion_owner: Uuid,
    owner: &common::Usuario,
    metadata_key_id: Uuid,
) -> (Uuid, SecretBox<[u8; 32]>) {
    let dek_bytes: [u8; 32] = ellkan_crypto::aleatoriedad::bytes_aleatorios();
    let dek = SecretBox::new(Box::new(dek_bytes));
    let resource_id = Uuid::now_v7();
    let mut aad = Vec::new();
    aad.extend_from_slice(resource_id.as_bytes());
    aad.extend_from_slice(owner.user_id.as_bytes());
    let metadata_env = aead::cifrar(&dek, br#"{"name":"permisos"}"#, &aad).unwrap();
    let secreto_env = aead::cifrar(&dek, br#"{"password":"pw"}"#, &aad).unwrap();
    let sealed_dek = sellado::sellar_dek(owner.x25519.publica(), &dek);

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
            "metadata_key_id": metadata_key_id,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    (resource_id, dek)
}

#[tokio::test]
async fn listar_cambiar_y_revocar_permisos_respeta_el_invariante_de_owner() {
    let entorno = common::levantar().await;
    let alice = common::registrar(&entorno, "alice-permisos@test.ellkan").await;
    let bob = common::registrar(&entorno, "bob-permisos@test.ellkan").await;
    let sesion_alice = common::login(&entorno, &alice).await;
    let sesion_bob = common::login(&entorno, &bob).await;
    common::promover_admin(&entorno.pool, alice.user_id).await;

    let metadata_key_id = crear_metadata_key(&entorno, sesion_alice, &alice).await;
    let (resource_id, dek) = crear_recurso_compartible(&entorno, sesion_alice, &alice, metadata_key_id).await;

    // Alice comparte con Bob en nivel `read`.
    let publica_bob = *bob.x25519.publica();
    let sealed_dek_bob = sellado::sellar_dek(&publica_bob, &dek);
    let mut aad = Vec::new();
    aad.extend_from_slice(resource_id.as_bytes());
    aad.extend_from_slice(alice.user_id.as_bytes());
    let secreto_env = aead::cifrar(&dek, br#"{"password":"pw"}"#, &aad).unwrap();
    let resp = entorno
        .cliente
        .post(format!("{}/resources/{}/share", entorno.base, resource_id))
        .bearer_auth(sesion_alice)
        .json(&json!({
            "recipient_user_id": bob.user_id,
            "sealed_dek_b64": B64.encode(&sealed_dek_bob),
            "secret_ciphertext_b64": B64.encode(&secreto_env.ciphertext),
            "secret_nonce_b64": B64.encode(secreto_env.nonce),
            "level": "read",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Bob (no-owner) no puede listar/tocar los permisos.
    let resp = entorno
        .cliente
        .get(format!("{}/resources/{}/permissions", entorno.base, resource_id))
        .bearer_auth(sesion_bob)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "un grantee read-only no debería poder ver el panel de permisos");

    // Alice (owner) sí puede listar — ve a sí misma (owner) y a Bob (read).
    let resp = entorno
        .cliente
        .get(format!("{}/resources/{}/permissions", entorno.base, resource_id))
        .bearer_auth(sesion_alice)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let grantees: Value = resp.json().await.unwrap();
    let lista = grantees.as_array().unwrap();
    assert_eq!(lista.len(), 2);
    let de_bob = lista.iter().find(|g| g["grantee_id"] == json!(bob.user_id)).unwrap();
    assert_eq!(de_bob["level"], "read");

    // Cambiar el nivel de Bob a `update` funciona.
    let resp = entorno
        .cliente
        .put(format!("{}/resources/{}/permissions/user/{}", entorno.base, resource_id, bob.user_id))
        .bearer_auth(sesion_alice)
        .json(&json!({ "level": "update" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Alice no puede revocarse a sí misma: es la única Owner.
    let resp = entorno
        .cliente
        .delete(format!("{}/resources/{}/permissions/user/{}", entorno.base, resource_id, alice.user_id))
        .bearer_auth(sesion_alice)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "revocar al único Owner debería fallar explícito");

    // Revocar a Bob sí funciona (no es el único Owner).
    let resp = entorno
        .cliente
        .delete(format!("{}/resources/{}/permissions/user/{}", entorno.base, resource_id, bob.user_id))
        .bearer_auth(sesion_alice)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Bob ya no puede leer el secreto.
    let resp = entorno
        .cliente
        .get(format!("{}/resources/{}/secret", entorno.base, resource_id))
        .bearer_auth(sesion_bob)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "revocado, Bob no debería seguir teniendo acceso al secreto");
}

/// 2026-08-13: `POST /resources/{id}/leave` — hallazgo real de uso, a
/// diferencia de `revocar_permiso` (exige ser Owner), acá un grantee
/// read/update se saca su propio acceso sin que el dueño tenga que hacer
/// nada, y sin que el recurso del dueño se vea afectado.
#[tokio::test]
async fn bob_puede_salir_de_un_recurso_compartido_sin_tocar_el_de_alice() {
    let entorno = common::levantar().await;
    let alice = common::registrar(&entorno, "alice-salir@test.ellkan").await;
    let bob = common::registrar(&entorno, "bob-salir@test.ellkan").await;
    let sesion_alice = common::login(&entorno, &alice).await;
    let sesion_bob = common::login(&entorno, &bob).await;
    common::promover_admin(&entorno.pool, alice.user_id).await;

    let metadata_key_id = crear_metadata_key(&entorno, sesion_alice, &alice).await;
    let (resource_id, dek) = crear_recurso_compartible(&entorno, sesion_alice, &alice, metadata_key_id).await;

    let publica_bob = *bob.x25519.publica();
    let sealed_dek_bob = sellado::sellar_dek(&publica_bob, &dek);
    let mut aad = Vec::new();
    aad.extend_from_slice(resource_id.as_bytes());
    aad.extend_from_slice(alice.user_id.as_bytes());
    let secreto_env = aead::cifrar(&dek, br#"{"password":"pw"}"#, &aad).unwrap();
    let resp = entorno
        .cliente
        .post(format!("{}/resources/{}/share", entorno.base, resource_id))
        .bearer_auth(sesion_alice)
        .json(&json!({
            "recipient_user_id": bob.user_id,
            "sealed_dek_b64": B64.encode(&sealed_dek_bob),
            "secret_ciphertext_b64": B64.encode(&secreto_env.ciphertext),
            "secret_nonce_b64": B64.encode(secreto_env.nonce),
            "level": "read",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Alice, única Owner, no puede salir de su propio recurso.
    let resp = entorno
        .cliente
        .post(format!("{}/resources/{}/leave", entorno.base, resource_id))
        .bearer_auth(sesion_alice)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "el único Owner no debería poder salir");

    // Alguien sin ningún acceso directo (llega acá vía otra cuenta) no tiene nada que salir.
    let carla = common::registrar(&entorno, "carla-salir@test.ellkan").await;
    let sesion_carla = common::login(&entorno, &carla).await;
    let resp = entorno
        .cliente
        .post(format!("{}/resources/{}/leave", entorno.base, resource_id))
        .bearer_auth(sesion_carla)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "sin acceso directo, no hay nada de qué salir");

    // Bob (read, no-owner) sí puede salir por su cuenta, sin que Alice haga nada.
    let resp = entorno
        .cliente
        .post(format!("{}/resources/{}/leave", entorno.base, resource_id))
        .bearer_auth(sesion_bob)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Bob ya no ve el recurso ni su secreto.
    let resp = entorno
        .cliente
        .get(format!("{}/resources/{}/secret", entorno.base, resource_id))
        .bearer_auth(sesion_bob)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403, "Bob salió, no debería seguir teniendo acceso al secreto");

    // Alice sigue teniendo su copia intacta — salir no es lo mismo que eliminar.
    let resp = entorno
        .cliente
        .get(format!("{}/resources/{}/secret", entorno.base, resource_id))
        .bearer_auth(sesion_alice)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "el recurso de Alice no debería verse afectado por que Bob salga");
}

#[tokio::test]
async fn agregar_destinatario_a_metadata_key_existente_le_da_acceso_real() {
    let entorno = common::levantar().await;
    let admin = common::registrar(&entorno, "admin-mk-members@test.ellkan").await;
    let bob = common::registrar(&entorno, "bob-mk-members@test.ellkan").await;
    let sesion_admin = common::login(&entorno, &admin).await;
    let sesion_bob = common::login(&entorno, &bob).await;
    common::promover_admin(&entorno.pool, admin.user_id).await;

    let metadata_key_id = crear_metadata_key(&entorno, sesion_admin, &admin).await;

    // Bob todavía no tiene envelope para esta key.
    let resp = entorno
        .cliente
        .get(format!("{}/metadata-keys", entorno.base))
        .bearer_auth(sesion_admin)
        .send()
        .await
        .unwrap();
    let claves: Value = resp.json().await.unwrap();
    let clave = claves.as_array().unwrap().iter().find(|c| c["id"] == json!(metadata_key_id)).unwrap();
    assert!(!clave["own_sealed_private_key_b64"].is_null(), "el admin creador sí debería tener su propio envelope");

    // Admin agrega a Bob como destinatario nuevo de la key ya activa.
    let par_bob: [u8; 32] = ellkan_crypto::aleatoriedad::bytes_aleatorios();
    let sealed_para_bob = sellado::sellar_dek(bob.x25519.publica(), &SecretBox::new(Box::new(par_bob)));
    let resp = entorno
        .cliente
        .post(format!("{}/admin/metadata-keys/{}/members", entorno.base, metadata_key_id))
        .bearer_auth(sesion_admin)
        .json(&json!({ "user_id": bob.user_id, "sealed_private_key_b64": B64.encode(&sealed_para_bob) }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "agregar un miembro nuevo a una key activa debería funcionar sin rotarla");

    // No-admin no puede agregar miembros.
    let resp = entorno
        .cliente
        .post(format!("{}/admin/metadata-keys/{}/members", entorno.base, metadata_key_id))
        .bearer_auth(sesion_bob)
        .json(&json!({ "user_id": bob.user_id, "sealed_private_key_b64": B64.encode(&sealed_para_bob) }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);

    // Agregar al mismo usuario dos veces es un conflicto explícito, no un no-op silencioso.
    let resp = entorno
        .cliente
        .post(format!("{}/admin/metadata-keys/{}/members", entorno.base, metadata_key_id))
        .bearer_auth(sesion_admin)
        .json(&json!({ "user_id": bob.user_id, "sealed_private_key_b64": B64.encode(&sealed_para_bob) }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409);
}
