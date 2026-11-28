// Autor: Athan Espinoza

//! Pendiente #133: una cuenta creada por SSO (JIT) nace sin claves y las
//! sube una sola vez en su primer acceso; `GET /me` avisa que falta, y
//! `GET /auth/setup-status` dice si hay un proveedor configurado.

mod common;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Value, json};

fn claves(n: u8) -> Value {
    json!({
        "public_key_x25519_b64": B64.encode([n; 32]),
        "public_key_ed25519_b64": B64.encode([n + 1; 32]),
        "encrypted_private_key_blob_b64": B64.encode([n + 2; 80]),
        "private_key_nonce_b64": B64.encode([n + 3; 24]),
        "kdf_salt_b64": B64.encode([n + 4; 16]),
        "kdf_params": ellkan_crypto::derivacion::ParametrosKdf::ACTUAL,
        "auth_key_b64": B64.encode([7u8; 32]),
    })
}

async fn busca(entorno: &common::Entorno, sesion: uuid::Uuid, q: &str) -> Vec<String> {
    let lista: Vec<Value> = entorno
        .cliente
        .get(format!("{}/users/search", entorno.base))
        .query(&[("q", q)])
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    lista.iter().filter_map(|u| u["email"].as_str().map(str::to_owned)).collect()
}

async fn enrolar(entorno: &common::Entorno, sesion: uuid::Uuid, cuerpo: &Value) -> u16 {
    entorno
        .cliente
        .post(format!("{}/me/keys/enroll", entorno.base))
        .bearer_auth(sesion)
        .json(cuerpo)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

#[tokio::test]
async fn una_cuenta_sin_claves_las_enrola_una_sola_vez() {
    let entorno = common::levantar().await;
    let ana = common::registrar(&entorno, "ana@test.ellkan").await;
    let sesion = common::login(&entorno, &ana).await;
    let bob = common::registrar(&entorno, "bob@test.ellkan").await;
    let sesion_bob = common::login(&entorno, &bob).await;
    // Sin restricción por grupo, así el buscador muestra a todos y lo único
    // que puede esconder a ana es no tener claves.
    sqlx::query("update sharing_policy set restrict_visibility_by_group = false")
        .execute(&entorno.pool)
        .await
        .unwrap();
    assert!(busca(&entorno, sesion_bob, "ana@").await.contains(&"ana@test.ellkan".to_string()));

    let perfil = |entorno: &common::Entorno| {
        let pedido = entorno.cliente.get(format!("{}/me", entorno.base)).bearer_auth(sesion).send();
        async move { pedido.await.unwrap().json::<Value>().await.unwrap() }
    };
    assert_eq!(perfil(&entorno).await["needs_key_enrollment"], false);

    // ELK-01 (#147, a2): una sesión que no emitió el callback SSO no enrola,
    // aunque sea válida.
    assert_eq!(enrolar(&entorno, sesion, &claves(10)).await, 403);

    // Desde acá la sesión pasa por emitida por SSO.
    sqlx::query("update sessions set emitida_por_sso = true where id = $1")
        .bind(sesion)
        .execute(&entorno.pool)
        .await
        .unwrap();

    // Una cuenta con claves no puede reemplazarlas por esta vía.
    assert_eq!(enrolar(&entorno, sesion, &claves(10)).await, 409);

    // Como la deja el alta JIT de SSO, SCIM o directorio (ELK-01 c): sin fila
    // en `user_keys`.
    sqlx::query("delete from user_keys where user_id = $1")
        .bind(ana.user_id)
        .execute(&entorno.pool)
        .await
        .unwrap();
    assert_eq!(perfil(&entorno).await["needs_key_enrollment"], true);
    // Sin claves no aparece como destinataria: nadie le puede sellar un secreto.
    assert!(!busca(&entorno, sesion_bob, "ana@").await.contains(&"ana@test.ellkan".to_string()));

    // Sesión SSO vieja (más de 30 min): ya no alcanza.
    sqlx::query("update sessions set created_at = now() - interval '31 minutes' where id = $1")
        .bind(sesion)
        .execute(&entorno.pool)
        .await
        .unwrap();
    assert_eq!(enrolar(&entorno, sesion, &claves(20)).await, 403);
    sqlx::query("update sessions set created_at = now() where id = $1")
        .bind(sesion)
        .execute(&entorno.pool)
        .await
        .unwrap();

    // Largos equivocados: 400, y no se guarda nada.
    let mut mal = claves(20);
    mal["private_key_nonce_b64"] = json!(B64.encode([1u8; 12]));
    assert_eq!(enrolar(&entorno, sesion, &mal).await, 400);

    assert_eq!(enrolar(&entorno, sesion, &claves(20)).await, 204);
    assert_eq!(perfil(&entorno).await["needs_key_enrollment"], false);
    let (publica,): (Vec<u8>,) = sqlx::query_as("select public_key_x25519 from user_keys where user_id = $1")
        .bind(ana.user_id)
        .fetch_one(&entorno.pool)
        .await
        .unwrap();
    assert_eq!(publica, vec![20u8; 32]);
    assert!(busca(&entorno, sesion_bob, "ana@").await.contains(&"ana@test.ellkan".to_string()));

    // Una segunda vez ya no: no pisa las claves recién creadas.
    assert_eq!(enrolar(&entorno, sesion, &claves(30)).await, 409);

    // La auditoría la escribe el consumidor de eventos, en segundo plano.
    let mut eventos = 0;
    for _ in 0..50 {
        (eventos,) =
            sqlx::query_as("select count(*) from audit_log_entries where event_type = 'user.keys_enrolled' and actor_user_id = $1")
                .bind(ana.user_id)
                .fetch_one(&entorno.pool)
                .await
                .unwrap();
        if eventos > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(eventos, 1i64);
}

/// ELK-01 (#147, c): la base ya no acepta una fila de relleno por ningún camino.
#[tokio::test]
async fn la_base_rechaza_claves_de_relleno() {
    let entorno = common::levantar().await;
    let ana = common::registrar(&entorno, "relleno@test.ellkan").await;
    for (sql, valor) in [
        ("update user_keys set public_key_x25519 = $2 where user_id = $1", vec![0u8; 32]),
        ("update user_keys set public_key_ed25519 = $2 where user_id = $1", vec![0u8; 32]),
        ("update user_keys set encrypted_private_key_blob = $2 where user_id = $1", Vec::new()),
    ] {
        let resultado = sqlx::query(sql).bind(ana.user_id).bind(valor).execute(&entorno.pool).await;
        assert!(resultado.is_err(), "la base tendría que rechazar el relleno: {sql}");
    }
}

#[tokio::test]
async fn setup_status_dice_si_hay_sso() {
    let entorno = common::levantar().await;
    let estado: Value = entorno
        .cliente
        .get(format!("{}/auth/setup-status", entorno.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(estado["sso_enabled"], false);
}
