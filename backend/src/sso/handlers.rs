// Autor: Athan Espinoza

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

use crate::auth::extractor::{AdminUser, AuthenticatedUser};
use crate::auth::models::ResultadoVerify;
use crate::error::ApiError;
use crate::state::AppState;

use super::dto::{ActualizarSsoConfigRequest, CallbackQuery, LoginCompletoResponse, SsoConfigResponse, VincularResponse};
use super::models::SsoConfig;
use super::repository::{PgLoginStateRepository, PgSsoConfigRepository, PgSsoIdentityRepository};
use super::service::{ResultadoCallback, SsoService};
use crate::auth::repository::PgUserRepository;

type Servicio<'a> = SsoService<'a, PgSsoConfigRepository, PgSsoIdentityRepository, PgLoginStateRepository, PgUserRepository>;

/// Adónde vuelve el IdP. Pendiente #133: por defecto, la página
/// `/sso/callback` de la web en la dirección pública (`ELLKAN_RP_ORIGIN`),
/// que le pasa `code`/`state` a `GET /auth/sso/oidc/callback` con `fetch`:
/// la sesión llega en el cuerpo y nunca pasa por una URL.
/// `ELLKAN_SSO_REDIRECT_URL` la reemplaza (debe coincidir con la registrada
/// en el IdP).
fn redirect_url(_state: &AppState) -> String {
    std::env::var("ELLKAN_SSO_REDIRECT_URL").unwrap_or_else(|_| {
        let origen = std::env::var("ELLKAN_RP_ORIGIN").unwrap_or_else(|_| "http://localhost:8080".to_string());
        format!("{}/sso/callback", origen.trim_end_matches('/'))
    })
}

/// QA-31 (login CSRF / fijación de sesión): el `state` se ata al navegador
/// que empezó el flujo con una cookie que guarda su hash. Un callback que
/// llega a otro navegador (alguien le hace abrir a la víctima un link con el
/// `code` y el `state` del atacante) no trae la cookie y se rechaza.
const COOKIE_STATE: &str = "ellkan_sso";

fn hash_state(state: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(state.as_bytes()))
}

fn cookie_state(valor: &str, max_age: i64) -> HeaderValue {
    let segura = std::env::var("ELLKAN_RP_ORIGIN").is_ok_and(|o| o.trim().starts_with("https://"));
    let cookie = format!(
        "{COOKIE_STATE}={valor}; Path=/auth/sso; Max-Age={max_age}; HttpOnly; SameSite=Lax{}",
        if segura { "; Secure" } else { "" }
    );
    HeaderValue::from_str(&cookie).expect("cookie ASCII")
}

fn cookie_coincide(headers: &HeaderMap, state: &str) -> bool {
    let esperado = hash_state(state);
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|par| par.trim().split_once('='))
        .any(|(nombre, valor)| {
            nombre == COOKIE_STATE
                && valor.len() == esperado.len()
                && valor.bytes().zip(esperado.bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
        })
}

fn servicio(state: &AppState) -> Servicio<'_> {
    SsoService {
        config: &state.sso_config,
        identities: &state.sso_identities,
        login_state: &state.sso_login_state,
        usuarios: &state.usuarios,
        redirect_url: redirect_url(state),
        eventos: state.eventos.clone(),
    }
}

#[allow(clippy::type_complexity)]
fn auth_service(
    state: &AppState,
) -> crate::auth::service::AuthService<
    '_,
    PgUserRepository,
    crate::auth::repository::PgAuthChallengeRepository,
    crate::auth::repository::PgSessionRepository,
    crate::auth::repository::PgKnownDeviceRepository,
    crate::auth::repository::PgDeviceChallengeRepository,
    crate::mfa::repository::PgMfaPolicyRepository,
    crate::mfa::repository::PgTotpCredentialRepository,
    crate::mfa::repository::PgMfaChallengeRepository,
    crate::smtp_config::repository::PgSmtpConfigRepository,
    crate::self_registration::repository::PgSelfRegistrationPolicyRepository,
    PgUserRepository,
> {
    crate::auth::service::AuthService {
        usuarios: &state.usuarios,
        challenges: &state.challenges,
        sesiones: &state.sesiones,
        dispositivos: &state.dispositivos,
        desafios_dispositivo: &state.desafios_dispositivo,
        mfa_policy: &state.mfa_policy,
        mfa_totp: &state.mfa_totp,
        mfa_challenges: &state.mfa_challenges,
        smtp_config: &state.smtp_config,
        self_registration: &state.self_registration_policy,
        email_verification: &state.usuarios,
        eventos: state.eventos.clone(),
    }
}

pub async fn config(State(state): State<AppState>, _admin: AdminUser) -> Result<Json<SsoConfigResponse>, ApiError> {
    let c = servicio(&state).config().await?;
    Ok(Json(SsoConfigResponse {
        issuer_url: c.issuer_url,
        client_id: c.client_id,
        jit_provisioning_enabled: c.jit_provisioning_enabled,
    }))
}

pub async fn actualizar_config(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(req): Json<ActualizarSsoConfigRequest>,
) -> Result<Json<SsoConfigResponse>, ApiError> {
    let nueva = SsoConfig {
        issuer_url: req.issuer_url,
        client_id: req.client_id,
        jit_provisioning_enabled: req.jit_provisioning_enabled,
    };
    let c = servicio(&state).actualizar_config(admin.user_id, nueva).await?;
    Ok(Json(SsoConfigResponse {
        issuer_url: c.issuer_url,
        client_id: c.client_id,
        jit_provisioning_enabled: c.jit_provisioning_enabled,
    }))
}

/// `GET /auth/sso/{provider}/redirect` — sólo `oidc` implementado (SAML
/// pospuesto, F-17). Redirect real (302) para un browser; nuestros tests de
/// integración lo siguen manualmente para poder inspeccionar la URL.
pub async fn redirect(State(state): State<AppState>, Path(provider): Path<String>) -> Result<Response, ApiError> {
    if provider != "oidc" {
        return Ok((StatusCode::NOT_FOUND, "proveedor no soportado").into_response());
    }
    let (url, sso_state) = servicio(&state).iniciar(None).await?;
    let mut respuesta = Redirect::to(&url).into_response();
    respuesta.headers_mut().append(header::SET_COOKIE, cookie_state(&hash_state(&sso_state), 600));
    Ok(respuesta)
}

/// `POST /me/sso/link` (QA-31): la única forma de vincular el inicio de
/// sesión de la organización a una cuenta que ya existe. Devuelve la URL del
/// IdP y deja la cookie del `state`; al volver, el callback vincula la
/// identidad a esta cuenta en vez de iniciar sesión.
pub async fn vincular(State(state): State<AppState>, auth: AuthenticatedUser) -> Result<Response, ApiError> {
    let (url, sso_state) = servicio(&state).iniciar(Some(auth.user_id)).await?;
    let mut respuesta = Json(VincularResponse { authorization_url: url }).into_response();
    respuesta.headers_mut().append(header::SET_COOKIE, cookie_state(&hash_state(&sso_state), 600));
    Ok(respuesta)
}

pub async fn callback(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Result<Response, ApiError> {
    if provider != "oidc" {
        return Err(crate::error::DomainError::NotFound.into());
    }
    // QA-31: antes de consumir el `state`, que no se pueda quemar desde otro navegador.
    if !cookie_coincide(&headers, &query.state) {
        return Err(crate::error::DomainError::InvalidCredentials.into());
    }
    let borrar_cookie = cookie_state("", 0);
    let user = match servicio(&state).resolver_callback(query.code, &query.state).await? {
        ResultadoCallback::Login(user) => user,
        ResultadoCallback::Vinculado(_) => {
            let mut respuesta = Json(LoginCompletoResponse { estado: "vinculado".into(), session_id: None }).into_response();
            respuesta.headers_mut().append(header::SET_COOKIE, borrar_cookie);
            return Ok(respuesta);
        }
    };

    // SSO no tiene un `device_token_hash` real (es un redirect 302 del IdP,
    // no un fetch con el token de `localStorage` adjunto) — un slice vacío
    // nunca matchea ningún hash real de `known_devices`, así que esto
    // equivale a "MFA nunca recordado por SSO", el mismo comportamiento que
    // ya tenía antes de este cambio.
    let resultado = auth_service(&state).resolver_tras_f02(user, &[], false).await?;

    let mut respuesta = Json(match resultado {
        ResultadoVerify::SesionCompleta(s) => LoginCompletoResponse { estado: "completo".into(), session_id: Some(s.id) },
        ResultadoVerify::PendienteMfa { session_id } => {
            LoginCompletoResponse { estado: "pendiente_mfa".into(), session_id: Some(session_id) }
        }
        ResultadoVerify::RequiereConfigurarMfa { session_id } => {
            LoginCompletoResponse { estado: "requiere_configurar_mfa".into(), session_id: Some(session_id) }
        }
        // SSO JIT/linking nunca marca `must_change_passphrase` (sólo
        // `AuthService::crear_por_admin` lo hace) — inalcanzable en la
        // práctica, pero el match tiene que ser exhaustivo igual.
        ResultadoVerify::RequiereCambiarPassphrase { session_id } => {
            LoginCompletoResponse { estado: "requiere_cambiar_passphrase".into(), session_id: Some(session_id) }
        }
        ResultadoVerify::PendienteDispositivo { .. } => unreachable!("SSO nunca pasa por F-02"),
    })
    .into_response();
    respuesta.headers_mut().append(header::SET_COOKIE, borrar_cookie);
    Ok(respuesta)
}
