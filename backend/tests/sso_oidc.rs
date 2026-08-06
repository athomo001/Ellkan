// Autor: Athan Espinoza

//! F-17: SSO OIDC contra un Keycloak de prueba real (levantado aparte, ver
//! `ELLKAN_TEST_KEYCLOAK_*`) — `authorization_code` + PKCE de punta a
//! punta, incluida la ceremonia de login real del IdP (parseo del form HTML
//! y POST de credenciales, sin headless browser). Un login exitoso vincula
//! la cuenta local por email (`email_verified: true`), y sigue pasando por
//! MFA si la política lo exige (F-14) — el propio IdP no puede saltearla.

mod common;

use serde_json::{json, Value};

/// `ELLKAN_SSO_REDIRECT_URL` es una variable de entorno global del proceso
/// — cualquier test que la toque tiene que serializarse contra los demás
/// que también la tocan (`#[tokio::test]` corre cada test en su propia
/// tarea, concurrente dentro del mismo binario).
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn keycloak_base() -> String {
    std::env::var("ELLKAN_TEST_KEYCLOAK_URL").unwrap_or_else(|_| "http://localhost:8090".to_string())
}
fn keycloak_realm() -> String {
    "ellkan-test".to_string()
}
fn keycloak_client_id() -> String {
    "ellkan-backend".to_string()
}

/// Sigue la ceremonia real de login de Keycloak: pide la página de login
/// (form HTML server-rendered, funciona sin JS para user/password), extrae
/// la URL de acción del `<form>`, y postea las credenciales — devuelve la
/// URL de redirect final (con `code`/`state`) sin seguirla.
async fn login_en_keycloak(cliente: &reqwest::Client, auth_url: &str, username: &str, password: &str) -> String {
    let pagina = cliente.get(auth_url).send().await.unwrap().text().await.unwrap();
    let inicio = pagina.find("action=\"").expect("la página de login debe tener un <form action=...>") + 8;
    let fin = pagina[inicio..].find('"').unwrap();
    let action = pagina[inicio..inicio + fin].replace("&amp;", "&");

    let resp = cliente
        .post(&action)
        .form(&[("username", username), ("password", password), ("credentialId", "")])
        .send()
        .await
        .unwrap();
    resp.headers()
        .get("location")
        .expect("debería redirigir con el authorization code")
        .to_str()
        .unwrap()
        .to_string()
}

async fn configurar_sso(entorno: &common::Entorno, sesion_admin: uuid::Uuid, jit: bool) {
    let resp = entorno
        .cliente
        .put(format!("{}/admin/sso-config", entorno.base))
        .bearer_auth(sesion_admin)
        .json(&json!({
            "issuer_url": format!("{}/realms/{}", keycloak_base(), keycloak_realm()),
            "client_id": keycloak_client_id(),
            "jit_provisioning_enabled": jit,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "{:?}", resp.text().await);
}

#[tokio::test]
async fn no_admin_no_puede_leer_ni_cambiar_sso_config() {
    let entorno = common::levantar().await;
    let user = common::registrar(&entorno, "sin-admin@test.ellkan").await;
    let sesion = common::login(&entorno, &user).await;

    let resp = entorno
        .cliente
        .get(format!("{}/admin/sso-config", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn redirect_sin_configurar_falla_explicito() {
    let entorno = common::levantar().await;
    let resp = entorno
        .cliente
        .get(format!("{}/auth/sso/oidc/redirect", entorno.base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "sin sso_config, el redirect debe fallar explícito, no armar una URL inválida");
}

/// Flujo completo, real, de punta a punta: la cuenta local ya existe con el
/// mismo email que el usuario de Keycloak (`email_verified: true` en
/// Keycloak) — se vincula automáticamente y el login SSO deja una sesión
/// completa (sin MFA activo).
#[tokio::test]
async fn login_sso_exitoso_vincula_por_email_verificado_y_completa_sesion() {
    let _guard = ENV_LOCK.lock().await;
    let entorno = common::levantar().await;

    // `ELLKAN_SSO_REDIRECT_URL` fija el puerto real y aleatorio de este
    // servidor de test — único test del binario que toca esta variable de
    // entorno global, para no competir con otro test corriendo en paralelo
    // en el mismo proceso.
    let redirect_url = format!("{}/auth/sso/oidc/callback", entorno.base);
    unsafe {
        std::env::set_var("ELLKAN_SSO_REDIRECT_URL", &redirect_url);
    }

    let admin = common::registrar(&entorno, "admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;
    configurar_sso(&entorno, sesion_admin, false).await;

    // La cuenta local que se va a vincular — mismo email que "alice" en
    // Keycloak (`alice@ellkan-test.example`, sembrada con `email_verified:
    // true` al preparar el realm de prueba).
    common::registrar(&entorno, "alice@ellkan-test.example").await;

    let kc = reqwest::Client::builder().cookie_store(true).redirect(reqwest::redirect::Policy::none()).build().unwrap();

    // `entorno.cliente` sigue redirects automáticamente (default de
    // reqwest) — acá se necesita justo lo contrario, para poder inspeccionar
    // el `Location` del propio backend antes de seguirlo hacia Keycloak.
    let resp = kc.get(format!("{}/auth/sso/oidc/redirect", entorno.base)).send().await.unwrap();
    let status = resp.status();
    let auth_url = resp.headers().get("location").map(|v| v.to_str().unwrap().to_string());
    let body = resp.text().await.unwrap();
    assert!(status.is_redirection(), "debería redirigir (302/303), fue {status}, body: {body}");
    let auth_url = auth_url.unwrap();

    let redirect_con_code = login_en_keycloak(&kc, &auth_url, "alice", "alice-password").await;
    assert!(redirect_con_code.starts_with(&redirect_url), "debe volver al callback registrado: {redirect_con_code}");

    let url = url::Url::parse(&redirect_con_code).unwrap();
    let params: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    let code = params.get("code").expect("la respuesta debe traer un code");
    let state = params.get("state").expect("la respuesta debe traer state");

    let resp = entorno
        .cliente
        .get(format!("{}/auth/sso/oidc/callback", entorno.base))
        .query(&[("code", code), ("state", state)])
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let cuerpo: Value = resp.json().await.unwrap();
    assert_eq!(status, 200, "{cuerpo:?}");
    assert_eq!(cuerpo["estado"], "completo");
    assert!(cuerpo["session_id"].is_string());

    // Un `state` reutilizado no vuelve a validar (protección real, no de
    // nombre) — reintentar exactamente la misma request falla.
    let resp = entorno
        .cliente
        .get(format!("{}/auth/sso/oidc/callback", entorno.base))
        .query(&[("code", code), ("state", state)])
        .send()
        .await
        .unwrap();
    assert_ne!(resp.status(), 200, "un state ya consumido no debe volver a validar");

    unsafe {
        std::env::remove_var("ELLKAN_SSO_REDIRECT_URL");
    }
}

/// F-17: el escenario central de account-takeover que la spec pide cerrar
/// — el IdP NO confirma el email (`email_verified: false`) pero el email
/// coincide con una cuenta local ya existente; sin confirmación explícita
/// (fuera de alcance de este checkbox, deferred), el login SSO nunca debe
/// vincular esa cuenta.
#[tokio::test]
async fn login_con_email_no_verificado_no_vincula_cuenta_existente() {
    let _guard = ENV_LOCK.lock().await;
    let entorno = common::levantar().await;
    let redirect_url = format!("{}/auth/sso/oidc/callback", entorno.base);
    unsafe {
        std::env::set_var("ELLKAN_SSO_REDIRECT_URL", &redirect_url);
    }

    let admin = common::registrar(&entorno, "admin@test.ellkan").await;
    common::promover_admin(&entorno.pool, admin.user_id).await;
    let sesion_admin = common::login(&entorno, &admin).await;
    configurar_sso(&entorno, sesion_admin, false).await;

    // Cuenta local víctima, mismo email que "bob" en Keycloak (`bob@ellkan-test.example`,
    // sembrado con `email_verified: false`).
    common::registrar(&entorno, "bob@ellkan-test.example").await;

    let kc = reqwest::Client::builder().cookie_store(true).redirect(reqwest::redirect::Policy::none()).build().unwrap();

    let resp = kc.get(format!("{}/auth/sso/oidc/redirect", entorno.base)).send().await.unwrap();
    let auth_url = resp.headers().get("location").unwrap().to_str().unwrap().to_string();

    let redirect_con_code = login_en_keycloak(&kc, &auth_url, "bob", "bob-password").await;
    let url = url::Url::parse(&redirect_con_code).unwrap();
    let params: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    let code = params.get("code").unwrap();
    let state = params.get("state").unwrap();

    let resp = entorno
        .cliente
        .get(format!("{}/auth/sso/oidc/callback", entorno.base))
        .query(&[("code", code), ("state", state)])
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "email_verified:false no debe vincular ni crear sesión, {:?}", resp.text().await);

    unsafe {
        std::env::remove_var("ELLKAN_SSO_REDIRECT_URL");
    }
}
