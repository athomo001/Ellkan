// Autor: Athan Espinoza

//! F-03: ceremonia WebAuthn real de punta a punta (registro + login), sin
//! navegador ni hardware, usando `SoftPasskey` (autenticador de software
//! protocolo-compatible, mismo proyecto que `webauthn-rs`). La extensión PRF
//! es 100% client-side — acá sólo se verifica que el blob opaco
//! (`prf_wrapped_private_key`) persiste correctamente según lo que el
//! cliente decida mandar, no que "desbloquee" nada (eso es responsabilidad
//! del frontend, 1.4).

mod common;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};
use webauthn_authenticator_rs::prelude::{Url, WebauthnAuthenticator};
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::{CreationChallengeResponse, PublicKeyCredential, RequestChallengeResponse};

fn origin() -> Url {
    // Debe coincidir con el default de `ELLKAN_RP_ORIGIN` del propio
    // servidor (`http://localhost:8080`) — independiente del puerto real en
    // el que el test levanta su instancia (`SoftPasskey` no valida contra
    // eso, sólo contra lo que el RP tiene configurado).
    Url::parse("http://localhost:8080").unwrap()
}

#[tokio::test]
async fn registrar_y_loguear_con_passkey_sin_prf_dos_veces() {
    let entorno = common::levantar().await;
    let usuario = common::registrar(&entorno, "passkey-1@test.ellkan").await;
    let sesion = common::login(&entorno, &usuario).await;

    let mut authenticador = SoftPasskey::new(true);

    // --- Registro ---
    let resp = entorno
        .cliente
        .post(format!("{}/auth/webauthn/register/options", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "register/options debería devolver 200");
    let ccr: CreationChallengeResponse = resp.json().await.unwrap();

    let credencial = authenticador.do_registration(origin(), ccr).expect("ceremonia de registro debería completar");

    let resp = entorno
        .cliente
        .post(format!("{}/auth/webauthn/register/verify", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({ "credential": credencial, "label": "authenticator de prueba" }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let texto = resp.text().await.unwrap();
    assert_eq!(status, 200, "register/verify debería devolver 200, body: {texto}");

    // --- Primer login vía passkey (sin passphrase) ---
    let sesion_id_1 = loguear_con_passkey(&entorno, &usuario.email, &mut authenticador).await;
    assert!(!sesion_id_1.is_empty());

    // --- Segundo login: confirma que el contador se actualiza sin romper
    // la validación (un contador que retrocediera sería rechazado) ---
    let sesion_id_2 = loguear_con_passkey(&entorno, &usuario.email, &mut authenticador).await;
    assert!(!sesion_id_2.is_empty());
    assert_ne!(sesion_id_1, sesion_id_2, "cada login emite una sesión nueva");
}

async fn loguear_con_passkey(entorno: &common::Entorno, email: &str, authenticador: &mut SoftPasskey) -> String {
    let resp = entorno
        .cliente
        .post(format!("{}/auth/webauthn/login/options", entorno.base))
        .json(&json!({ "email": email }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "login/options debería devolver 200 para un usuario con passkeys");
    let rcr: RequestChallengeResponse = resp.json().await.unwrap();

    let credencial: PublicKeyCredential =
        authenticador.do_authentication(origin(), rcr).expect("ceremonia de autenticación debería completar");

    let resp = entorno
        .cliente
        .post(format!("{}/auth/webauthn/login/verify", entorno.base))
        .json(&json!({ "email": email, "credential": credencial }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let texto = resp.text().await.unwrap();
    assert_eq!(status, 200, "login/verify debería devolver 200, body: {texto}");
    let cuerpo: Value = serde_json::from_str(&texto).unwrap();
    cuerpo["session_id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn prf_wrapped_private_key_persiste_solo_cuando_el_cliente_lo_manda() {
    let entorno = common::levantar().await;
    let usuario = common::registrar(&entorno, "passkey-2@test.ellkan").await;
    let sesion = common::login(&entorno, &usuario).await;
    let mut authenticador = SoftPasskey::new(true);

    // --- Passkey CON PRF (blob opaco, el servidor no lo interpreta) ---
    let resp = entorno
        .cliente
        .post(format!("{}/auth/webauthn/register/options", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    let ccr: CreationChallengeResponse = resp.json().await.unwrap();
    let credencial = authenticador.do_registration(origin(), ccr).unwrap();
    let blob_prf = b"blob-opaco-envuelto-client-side".to_vec();
    let resp = entorno
        .cliente
        .post(format!("{}/auth/webauthn/register/verify", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({
            "credential": credencial,
            "prf_wrapped_private_key_b64": B64.encode(&blob_prf),
            "label": "con-prf",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // --- Passkey SIN PRF ---
    let resp = entorno
        .cliente
        .post(format!("{}/auth/webauthn/register/options", entorno.base))
        .bearer_auth(sesion)
        .send()
        .await
        .unwrap();
    let ccr: CreationChallengeResponse = resp.json().await.unwrap();
    let credencial = authenticador.do_registration(origin(), ccr).unwrap();
    let resp = entorno
        .cliente
        .post(format!("{}/auth/webauthn/register/verify", entorno.base))
        .bearer_auth(sesion)
        .json(&json!({ "credential": credencial, "label": "sin-prf" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let filas: Vec<(String, Option<Vec<u8>>)> =
        sqlx::query_as("select label, prf_wrapped_private_key from passkeys where user_id = $1 order by created_at")
            .bind(usuario.user_id)
            .fetch_all(&entorno.pool)
            .await
            .unwrap();
    assert_eq!(filas.len(), 2);
    assert_eq!(filas[0].0, "con-prf");
    assert_eq!(filas[0].1.as_deref(), Some(blob_prf.as_slice()));
    assert_eq!(filas[1].0, "sin-prf");
    assert_eq!(filas[1].1, None, "sin PRF, el campo debe quedar null");
}

#[tokio::test]
async fn login_sin_passkeys_o_usuario_inexistente_devuelve_401_uniforme() {
    let entorno = common::levantar().await;
    let usuario = common::registrar(&entorno, "passkey-3@test.ellkan").await;
    common::login(&entorno, &usuario).await;

    // Usuario existente, sin ninguna passkey registrada.
    let resp = entorno
        .cliente
        .post(format!("{}/auth/webauthn/login/options", entorno.base))
        .json(&json!({ "email": usuario.email }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // Usuario inexistente — mismo código, no distingue.
    let resp = entorno
        .cliente
        .post(format!("{}/auth/webauthn/login/options", entorno.base))
        .json(&json!({ "email": "no-existe@test.ellkan" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
}
