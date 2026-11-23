// Autor: Athan Espinoza

//! Service de SSO OIDC (F-17) — nunca importa `axum`. `authorization_code` +
//! PKCE obligatorio (S256): Ellkan es un cliente público, no hay secreto que
//! proteger en un backend que también sirve el frontend estático. La
//! verificación de firma/claims del `id_token` nunca se reimplementa a mano
//! — corre entera dentro de `openidconnect` contra el JWKS del propio IdP.

use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType};
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, CsrfToken, EndpointMaybeSet, EndpointNotSet, EndpointSet, IssuerUrl, Nonce,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::audit::models::{AuditEventType, EventoAuditoria};
use crate::auth::models::{NuevoUsuario, User};
use crate::auth::repository::UserRepository;
use crate::error::DomainError;
use crate::eventos::{DomainEvent, EmisorDeEventos};
use ellkan_crypto::aleatoriedad::bytes_aleatorios;

use super::models::{ResultadoLinking, SsoConfig};
use super::repository::{LoginStateRepository, SsoConfigRepository, SsoIdentityRepository};

const TTL_LOGIN_STATE_SEGUNDOS: i64 = 600;
const PROVIDER: &str = "oidc";

/// QA-31: un IdP lento no puede colgar solicitudes ni conexiones.
const TIMEOUT_IDP: std::time::Duration = std::time::Duration::from_secs(10);
/// QA-31: el documento de discovery se reutiliza este tiempo en vez de
/// pedirlo en cada login.
const TTL_DISCOVERY: std::time::Duration = std::time::Duration::from_secs(600);

static DISCOVERY: std::sync::Mutex<Option<(String, std::time::Instant, CoreProviderMetadata)>> = std::sync::Mutex::new(None);

/// Cliente HTTP hacia el IdP: con timeout y sin seguir redirecciones (que un
/// IdP comprometido no pueda mandar al servidor a pedir otra cosa).
fn http_idp() -> Result<openidconnect::reqwest::Client, SsoError> {
    openidconnect::reqwest::Client::builder()
        .timeout(TIMEOUT_IDP)
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| SsoError::Protocolo(e.to_string()))
}

/// Qué resolvió el callback: un login, o la vinculación pedida desde una sesión.
pub enum ResultadoCallback {
    Login(User),
    Vinculado(Uuid),
}

#[derive(Debug, thiserror::Error)]
pub enum SsoError {
    #[error("SSO no está configurado")]
    NoConfigurado,
    #[error("error de protocolo OIDC: {0}")]
    Protocolo(String),
    #[error("state inválido, vencido, o ya usado")]
    StateInvalido,
    #[error(
        "el IdP no confirmó el email (email_verified) y ya existe una cuenta local con ese email — no se vincula sin confirmación explícita"
    )]
    EmailNoVerificado,
    #[error("no existe una cuenta local con ese email y el aprovisionamiento automático está deshabilitado")]
    SinCuentaYJitDeshabilitado,
    #[error(
        "ya existe una cuenta con ese email: iniciá sesión con tu contraseña y vinculá el inicio de sesión de tu organización desde tu cuenta"
    )]
    CuentaLocalSinVincular,
    #[error("esa identidad de tu organización ya está vinculada a otra cuenta")]
    IdentidadDeOtraCuenta,
}

impl From<SsoError> for DomainError {
    fn from(e: SsoError) -> Self {
        match e {
            SsoError::NoConfigurado | SsoError::StateInvalido => DomainError::InvalidCredentials,
            SsoError::EmailNoVerificado
            | SsoError::SinCuentaYJitDeshabilitado
            | SsoError::CuentaLocalSinVincular
            | SsoError::IdentidadDeOtraCuenta => DomainError::ValidacionInvalida(e.to_string()),
            SsoError::Protocolo(_) => DomainError::InvalidCredentials,
        }
    }
}

pub struct SsoService<'a, C, I, L, U> {
    pub config: &'a C,
    pub identities: &'a I,
    pub login_state: &'a L,
    pub usuarios: &'a U,
    pub redirect_url: String,
    pub eventos: EmisorDeEventos,
}

impl<'a, C, I, L, U> SsoService<'a, C, I, L, U>
where
    C: SsoConfigRepository,
    I: SsoIdentityRepository,
    L: LoginStateRepository,
    U: UserRepository,
{
    pub async fn config(&self) -> Result<SsoConfig, DomainError> {
        Ok(self.config.obtener().await?)
    }

    pub async fn actualizar_config(&self, actor_id: Uuid, nueva: SsoConfig) -> Result<SsoConfig, DomainError> {
        self.config.actualizar(&nueva).await?;
        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::SsoConfigUpdated, Some(actor_id)).con_metadata(serde_json::json!({
                "issuer_url": nueva.issuer_url,
                "jit_provisioning_enabled": nueva.jit_provisioning_enabled,
            })),
        ));
        Ok(nueva)
    }

    #[allow(clippy::type_complexity)]
    async fn cliente(
        &self,
        cfg: &SsoConfig,
    ) -> Result<CoreClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet, EndpointMaybeSet>, SsoError> {
        let issuer_url = cfg.issuer_url.as_deref().ok_or(SsoError::NoConfigurado)?;
        let client_id = cfg.client_id.as_deref().ok_or(SsoError::NoConfigurado)?;

        let cacheado = DISCOVERY.lock().ok().and_then(|c| {
            c.as_ref()
                .filter(|(url, cuando, _)| url == issuer_url && cuando.elapsed() < TTL_DISCOVERY)
                .map(|(_, _, m)| m.clone())
        });
        let metadata = match cacheado {
            Some(m) => m,
            None => {
                let issuer = IssuerUrl::new(issuer_url.to_string()).map_err(|e| SsoError::Protocolo(e.to_string()))?;
                let m = CoreProviderMetadata::discover_async(issuer, &http_idp()?)
                    .await
                    .map_err(|e| SsoError::Protocolo(e.to_string()))?;
                if let Ok(mut c) = DISCOVERY.lock() {
                    *c = Some((issuer_url.to_string(), std::time::Instant::now(), m.clone()));
                }
                m
            }
        };
        // `from_provider_metadata` deja `token_url` en `EndpointMaybeSet`
        // (viene de un `Option` del documento de discovery) — se fija acá
        // explícito a `EndpointSet`, requisito de tipos de `exchange_code`
        // más abajo; si el IdP no publicara `token_endpoint` esto falla acá,
        // temprano y explícito, no silenciosamente más adelante.
        let token_url = metadata
            .token_endpoint()
            .cloned()
            .ok_or_else(|| SsoError::Protocolo("el IdP no publica token_endpoint".into()))?;

        let redirect = RedirectUrl::new(self.redirect_url.clone()).map_err(|e| SsoError::Protocolo(e.to_string()))?;
        Ok(CoreClient::from_provider_metadata(metadata, ClientId::new(client_id.to_string()), None)
            .set_redirect_uri(redirect)
            .set_token_uri(token_url))
    }

    /// `GET /auth/sso/oidc/redirect` (login) y `POST /me/sso/link`
    /// (vincular la cuenta de `link_user_id`) — arma la URL de autorización
    /// (`code_challenge` S256, `state`/`nonce` opacos de un solo uso) y
    /// persiste el estado server-side para poder validarlo en el callback.
    /// Devuelve también el `state`: el handler ata el navegador a él con una
    /// cookie (QA-31).
    pub async fn iniciar(&self, link_user_id: Option<Uuid>) -> Result<(String, String), DomainError> {
        let cfg = self.config.obtener().await?;
        let client = self.cliente(&cfg).await?;

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let (auth_url, csrf_token, nonce) = client
            .authorize_url(AuthenticationFlow::<CoreResponseType>::AuthorizationCode, CsrfToken::new_random, Nonce::new_random)
            .add_scope(Scope::new("email".to_string()))
            .set_pkce_challenge(pkce_challenge)
            .url();

        let expires_at = OffsetDateTime::now_utc() + time::Duration::seconds(TTL_LOGIN_STATE_SEGUNDOS);
        self.login_state
            .crear(csrf_token.secret(), nonce.secret(), pkce_verifier.secret(), expires_at, link_user_id)
            .await?;

        Ok((auth_url.to_string(), csrf_token.secret().clone()))
    }

    /// `GET /auth/sso/oidc/callback` — intercambia el `code` por tokens
    /// (con el `pkce_verifier` guardado, nunca uno recibido en la request),
    /// verifica firma/`nonce`/`aud`/`iss` del `id_token` contra el JWKS del
    /// IdP, y resuelve la vinculación de cuenta (F-17: ver
    /// `resolver_linking`).
    pub async fn resolver_callback(&self, code: String, state_recibido: &str) -> Result<ResultadoCallback, DomainError> {
        let cfg = self.config.obtener().await?;
        let estado = self.login_state.consumir(state_recibido).await?.ok_or(SsoError::StateInvalido)?;

        let client = self.cliente(&cfg).await?;

        let token_response = client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(PkceCodeVerifier::new(estado.pkce_verifier))
            .request_async(&http_idp()?)
            .await
            .map_err(|e| SsoError::Protocolo(e.to_string()))?;

        let id_token = token_response.id_token().ok_or(SsoError::Protocolo("respuesta sin id_token".into()))?;
        let claims = id_token
            .claims(&client.id_token_verifier(), &Nonce::new(estado.nonce))
            .map_err(|e| SsoError::Protocolo(e.to_string()))?;

        let sub = claims.subject().to_string();
        let email = claims.email().map(|e| e.to_string());
        let email_verified = claims.email_verified().unwrap_or(false);

        if let Some(user_id) = estado.link_user_id {
            return self.vincular_a(user_id, &sub, email.as_deref()).await.map(ResultadoCallback::Vinculado);
        }

        let resultado_linking = self.resolver_linking(&cfg, &sub, email.as_deref(), email_verified).await?;

        let user_id = match resultado_linking {
            ResultadoLinking::Vinculado(id) => id,
            ResultadoLinking::RechazadoEmailNoVerificado => {
                let _ = self
                    .eventos
                    .send(DomainEvent::Auditoria(EventoAuditoria::nuevo(AuditEventType::SsoLinkRejectedUnverifiedEmail, None)));
                return Err(SsoError::EmailNoVerificado.into());
            }
            ResultadoLinking::SinCuentaYJitDeshabilitado => {
                return Err(SsoError::SinCuentaYJitDeshabilitado.into());
            }
            ResultadoLinking::CuentaLocalSinVincular => {
                return Err(SsoError::CuentaLocalSinVincular.into());
            }
        };

        let user = self.usuarios.buscar_por_id(user_id).await?.ok_or(DomainError::InvalidCredentials)?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::SsoLoginSucceeded, Some(user_id)).con_sujeto("user", user_id),
        ));

        Ok(ResultadoCallback::Login(user))
    }

    /// QA-31: vincula la identidad del IdP a la cuenta que pidió el flujo
    /// desde su propia sesión. Idempotente si ya era suya; nunca le quita la
    /// identidad a otra cuenta.
    async fn vincular_a(&self, user_id: Uuid, sub: &str, email: Option<&str>) -> Result<Uuid, DomainError> {
        match self.identities.buscar_user_id_por_identidad(PROVIDER, sub).await? {
            Some(actual) if actual == user_id => return Ok(user_id),
            Some(_) => return Err(SsoError::IdentidadDeOtraCuenta.into()),
            None => {}
        }
        self.identities
            .vincular(user_id, PROVIDER, sub, serde_json::json!({ "email": email }))
            .await
            .map_err(|e| match e {
                crate::error::RepoError::Conflict => SsoError::IdentidadDeOtraCuenta.into(),
                otro => DomainError::Interno(otro),
            })?;
        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::SsoAccountLinked, Some(user_id)).con_sujeto("user", user_id),
        ));
        Ok(user_id)
    }

    /// F-17: vinculación de cuenta al primer login SSO — decisión explícita,
    /// riesgo real de account takeover si se hace mal (informado por la
    /// cascada real de Bitwarden). Identidad ya vinculada matchea por
    /// `sso_identities.provider_user_id` (nunca re-derivada por email en
    /// cada login); primer login resuelve por email según `email_verified`.
    async fn resolver_linking(
        &self,
        cfg: &SsoConfig,
        sub: &str,
        email: Option<&str>,
        email_verified: bool,
    ) -> Result<ResultadoLinking, DomainError> {
        if let Some(user_id) = self.identities.buscar_user_id_por_identidad(PROVIDER, sub).await? {
            return Ok(ResultadoLinking::Vinculado(user_id));
        }

        let Some(email) = email else {
            return Ok(ResultadoLinking::SinCuentaYJitDeshabilitado);
        };

        // QA-31: una cuenta local existente ya no se vincula sola por el
        // `email_verified` del IdP (un IdP mal configurado o multi-tenant
        // podía quedarse con ella): la vincula su dueño desde su sesión.
        if self.usuarios.buscar_por_email(email).await?.is_some() {
            if !email_verified {
                return Ok(ResultadoLinking::RechazadoEmailNoVerificado);
            }
            return Ok(ResultadoLinking::CuentaLocalSinVincular);
        }

        if !cfg.jit_provisioning_enabled {
            return Ok(ResultadoLinking::SinCuentaYJitDeshabilitado);
        }

        // JIT provisioning: alta nueva sin ninguna clave criptográfica
        // propia todavía — el usuario completa el enrolamiento
        // (Argon2id/keypair, F-01) en su primer acceso real, mismo criterio
        // que una invitación normal, nunca con acceso implícito a nada.
        // F-24: `ya_verificado: true` — el IdP ya vouched por este email
        // (`email_verified` del token, chequeado arriba); no vuelve a pasar
        // por la verificación de auto-registro público.
        let nuevo = self
            .usuarios
            .crear(
                NuevoUsuario {
                    email,
                    display_name: email,
                    public_key_x25519: &[0u8; 32],
                    public_key_ed25519: &[0u8; 32],
                    encrypted_private_key_blob: &[],
                    private_key_nonce: &bytes_aleatorios::<24>(),
                    kdf_salt: &bytes_aleatorios::<16>(),
                    // Sin claves todavía: sin verificador hasta `POST /me/keys/enroll`.
                    kdf_params: ellkan_crypto::derivacion::ParametrosKdf::LEGADO,
                    auth_key: None,
                },
                true,
            )
            .await
            // H-41 (auditoría 2026-08-12): dos callbacks OIDC concurrentes
            // para el mismo email nuevo pueden ambos llegar hasta acá; el
            // constraint único de `users.email` evita el duplicado, pero el
            // perdedor de la carrera recibía un 500 genérico (`Interno`) en
            // vez de un 409 — `crear` ya mapea la violación a
            // `RepoError::Conflict`, sólo hacía falta no perderlo acá.
            .map_err(|e| match e {
                crate::error::RepoError::Conflict => DomainError::Conflict,
                otro => DomainError::Interno(otro),
            })?;

        self.identities.vincular(nuevo.id, PROVIDER, sub, serde_json::json!({ "email": email })).await?;
        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::SsoJitProvisioned, Some(nuevo.id)).con_sujeto("user", nuevo.id),
        ));

        Ok(ResultadoLinking::Vinculado(nuevo.id))
    }
}
