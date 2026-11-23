// Autor: Athan Espinoza

//! Bootstrap: el primer usuario que se auto-registra en una instancia sin
//! ningún usuario previo nace `admin`; cualquier registro posterior nace
//! `user` como siempre (`backend/src/auth/repository.rs::crear`).

mod common;

#[tokio::test]
async fn primer_usuario_de_una_instancia_nueva_nace_admin() {
    let entorno = common::levantar_sin_usuarios().await;
    let primero = common::registrar(&entorno, "primer-usuario@test.ellkan").await;

    let rol: String = sqlx::query_scalar("select r.name from users u join roles r on r.id = u.role_id where u.id = $1")
        .bind(primero.user_id)
        .fetch_one(&entorno.pool)
        .await
        .unwrap();

    assert_eq!(rol, "admin", "el primer registro de una instancia nueva debe nacer admin");
}

#[tokio::test]
async fn segundo_usuario_nace_user_aunque_el_primero_ya_sea_admin() {
    let entorno = common::levantar_sin_usuarios().await;
    common::registrar(&entorno, "primero@test.ellkan").await;
    let segundo = common::registrar(&entorno, "segundo@test.ellkan").await;

    let rol: String = sqlx::query_scalar("select r.name from users u join roles r on r.id = u.role_id where u.id = $1")
        .bind(segundo.user_id)
        .fetch_one(&entorno.pool)
        .await
        .unwrap();

    assert_eq!(rol, "user", "a partir del segundo registro, sigue naciendo user como siempre");
}

async fn registrar_crudo(entorno: &common::Entorno, email: &str, setup_token: Option<&str>) -> u16 {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;
    let mut cuerpo = serde_json::json!({
        "email": email,
        "display_name": email,
        "public_key_x25519_b64": B64.encode([1u8; 32]),
        "public_key_ed25519_b64": B64.encode([2u8; 32]),
        "encrypted_private_key_blob_b64": B64.encode([3u8; 80]),
        "private_key_nonce_b64": B64.encode([4u8; 24]),
        "kdf_salt_b64": B64.encode([5u8; 16]),
        "kdf_params": ellkan_crypto::derivacion::ParametrosKdf::ACTUAL,
        "auth_key_b64": B64.encode([7u8; 32]),
    });
    if let Some(t) = setup_token {
        cuerpo["setup_token"] = serde_json::Value::String(t.to_string());
    }
    entorno
        .cliente
        .post(format!("{}/auth/register", entorno.base))
        .json(&cuerpo)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

/// QA-11: con `ELLKAN_SETUP_TOKEN` configurado, el registro que nacería
/// admin en una instancia vacía exige el token.
#[tokio::test]
async fn con_token_de_instalacion_el_primer_registro_lo_exige() {
    let token = "token-de-instalacion-de-prueba-0123456789";
    let entorno = common::levantar_sin_usuarios_con_setup_token(token).await;

    assert_eq!(registrar_crudo(&entorno, "sin-token@test.ellkan", None).await, 403);
    assert_eq!(
        registrar_crudo(&entorno, "token-malo@test.ellkan", Some("token-incorrecto-0123456789abc")).await,
        403
    );
    let usuarios: i64 = sqlx::query_scalar("select count(*) from users").fetch_one(&entorno.pool).await.unwrap();
    assert_eq!(usuarios, 0, "un registro rechazado no debe crear nada");

    assert_eq!(registrar_crudo(&entorno, "operador@test.ellkan", Some(token)).await, 200);
    let rol: String =
        sqlx::query_scalar("select r.name from users u join roles r on r.id = u.role_id where u.email = 'operador@test.ellkan'")
            .fetch_one(&entorno.pool)
            .await
            .unwrap();
    assert_eq!(rol, "admin");
}

/// QA-11: dos registros simultáneos en una instancia vacía nunca dejan dos
/// admins (lock transaccional sobre el alta).
#[tokio::test]
async fn registros_simultaneos_en_instancia_vacia_dejan_un_solo_admin() {
    let entorno = common::levantar_sin_usuarios().await;
    let (a, b, c) = tokio::join!(
        registrar_crudo(&entorno, "carrera-a@test.ellkan", None),
        registrar_crudo(&entorno, "carrera-b@test.ellkan", None),
        registrar_crudo(&entorno, "carrera-c@test.ellkan", None),
    );
    assert!([a, b, c].contains(&200));
    let admins: i64 = sqlx::query_scalar("select count(*) from users u join roles r on r.id = u.role_id where r.name = 'admin'")
        .fetch_one(&entorno.pool)
        .await
        .unwrap();
    assert_eq!(admins, 1);
}

async fn setup_status(entorno: &common::Entorno) -> bool {
    let resp: serde_json::Value = entorno
        .cliente
        .get(format!("{}/auth/setup-status", entorno.base))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    resp["setup_token_required"].as_bool().expect("setup_token_required booleano")
}

/// Pendiente #109: la pantalla de registro pregunta si tiene que pedir el
/// token. Sólo es `true` con la instancia vacía y un token configurado; en
/// cuanto existe la primera cuenta deja de pedirse.
#[tokio::test]
async fn setup_status_pide_el_token_solo_mientras_la_instancia_esta_vacia() {
    let token = "token-de-instalacion-de-prueba-0123456789";
    let entorno = common::levantar_sin_usuarios_con_setup_token(token).await;
    assert!(setup_status(&entorno).await, "instancia vacía con token: tiene que pedirlo");

    assert_eq!(registrar_crudo(&entorno, "operador-status@test.ellkan", Some(token)).await, 200);
    assert!(!setup_status(&entorno).await, "con la primera cuenta creada ya no se pide");
}

/// Sin token configurado (tests, escritorio) no se pide nada.
#[tokio::test]
async fn setup_status_no_pide_token_si_no_hay_uno_configurado() {
    let entorno = common::levantar_sin_usuarios().await;
    assert!(!setup_status(&entorno).await);
}
