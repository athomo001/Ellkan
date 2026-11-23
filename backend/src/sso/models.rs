// Autor: Athan Espinoza

use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct SsoConfig {
    pub issuer_url: Option<String>,
    pub client_id: Option<String>,
    pub jit_provisioning_enabled: bool,
}

#[derive(Debug, Clone)]
pub struct LoginState {
    pub state: String,
    pub nonce: String,
    pub pkce_verifier: String,
    pub expires_at: OffsetDateTime,
    /// QA-31: `Some` cuando el flujo lo inició una sesión para vincular su
    /// propia cuenta (`POST /me/sso/link`), no un login.
    pub link_user_id: Option<Uuid>,
}

/// Resultado de resolver la identidad OIDC contra una cuenta local — mismo
/// espíritu que `ResultadoVerify` (F-02/F-14), pero antes de siquiera saber
/// si hay un `user_id` para decidir sesión/MFA.
#[derive(Debug, Clone)]
pub enum ResultadoLinking {
    Vinculado(Uuid),
    RechazadoEmailNoVerificado,
    SinCuentaYJitDeshabilitado,
    /// QA-31: hay una cuenta local con ese email y todavía no está vinculada:
    /// sólo su dueño, con sesión iniciada, puede vincularla.
    CuentaLocalSinVincular,
}
