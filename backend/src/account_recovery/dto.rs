// Autor: Athan Espinoza

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct AccountRecoveryPolicyResponse {
    pub required: bool,
    pub grace_period_days: i32,
    pub default_approval_threshold: i32,
}

#[derive(Debug, Deserialize)]
pub struct ActualizarAccountRecoveryPolicyRequest {
    pub required: bool,
    pub grace_period_days: i32,
    pub default_approval_threshold: i32,
}

#[derive(Debug, Serialize)]
pub struct MiEstadoResponse {
    pub enrolled: bool,
    /// QA-09: clave contra la que está sellado el escrow propio y la
    /// vigente; si difieren, el cliente re-sella (rotación).
    pub org_recovery_key_id: Option<i32>,
    pub current_org_recovery_key_id: Option<i32>,
}

#[derive(Debug, Serialize)]
pub struct OrgPublicKeyResponse {
    pub id: i32,
    pub public_key_x25519_b64: String,
    /// `"client"` (la custodian los admins) o `"server"` (anterior a QA-09).
    pub custody: &'static str,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Deserialize)]
pub struct EnrolarRequest {
    pub sealed_private_key_for_org_b64: String,
    /// QA-09: contra qué clave se selló (409 si ya no es la vigente).
    pub org_recovery_key_id: i32,
}

/// QA-09: un admin de organización que todavía no tiene su copia de la
/// clave vigente.
#[derive(Debug, Serialize)]
pub struct CustodioPendienteResponse {
    pub user_id: Uuid,
    pub email: String,
    pub display_name: String,
    pub public_key_x25519_b64: String,
}

#[derive(Debug, Serialize)]
pub struct EstadoCustodiaResponse {
    pub current: Option<OrgPublicKeyResponse>,
    pub my_envelope_b64: Option<String>,
    pub pending_custodians: Vec<CustodioPendienteResponse>,
    pub org_admins: Vec<CustodioPendienteResponse>,
    pub escrows_on_server_key: i64,
}

#[derive(Debug, Deserialize)]
pub struct SobreRequest {
    pub admin_id: Uuid,
    pub sealed_private_key_b64: String,
}

#[derive(Debug, Deserialize)]
pub struct CrearClaveOrgRequest {
    pub public_key_x25519_b64: String,
    pub envelopes: Vec<SobreRequest>,
}

#[derive(Debug, Deserialize)]
pub struct AgregarCustodioRequest {
    pub admin_id: Uuid,
    pub sealed_private_key_b64: String,
}

#[derive(Debug, Serialize)]
pub struct CrearClaveOrgResponse {
    pub id: i32,
}

#[derive(Debug, Serialize)]
pub struct PurgaResponse {
    pub escrows_deleted: i64,
}

#[derive(Debug, Serialize)]
pub struct MaterialCustodioResponse {
    pub sealed_private_key_for_org_b64: String,
    pub requester_public_key_x25519_b64: String,
    pub org_recovery_key_id: i32,
    pub envelope_b64: String,
}

#[derive(Debug, Deserialize)]
pub struct EjecutarRequest {
    pub sealed_private_key_for_requester_b64: String,
}

#[derive(Debug, Serialize)]
pub struct EscrowResponse {
    pub id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Deserialize)]
pub struct CrearSolicitudRequest {
    pub email: String,
    pub requester_public_key_x25519_b64: String,
}

#[derive(Debug, Serialize)]
pub struct SolicitudResponse {
    pub id: Uuid,
    pub status: String,
    pub approvals_count: usize,
    pub sealed_private_key_for_requester_b64: Option<String>,
}

/// `POST /account-recovery/requests/{id}/complete` — mismos 3 campos que
/// `NuevaClavePrivada` (`crate::me::models`): el cliente ya desselló el
/// material del escrow con su clave efímera y lo re-selló contra una
/// passphrase nueva antes de llamar acá.
#[derive(Debug, Deserialize)]
pub struct ConfirmarSolicitudRequest {
    pub code: String,
}

/// QA-10: el token sólo se entrega una vez, al confirmar el código; el
/// cliente lo manda en `X-Ellkan-Recovery-Token` al consultar el estado y en
/// el cuerpo al completar.
#[derive(Debug, Serialize)]
pub struct ConfirmarSolicitudResponse {
    pub requester_token_b64: String,
}

#[derive(Debug, Deserialize)]
pub struct CompletarSolicitudRequest {
    pub requester_token_b64: String,
    pub encrypted_private_key_blob_b64: String,
    pub private_key_nonce_b64: String,
    pub kdf_salt_b64: String,
    /// QA-03: parámetros de Argon2id del blob y `auth_key` del mismo Argon2id
    /// (los dos entran en la firma).
    pub kdf_params: ellkan_crypto::derivacion::ParametrosKdf,
    pub auth_key_b64: String,
    /// QA-06: nonce de `POST /auth/challenge` (un solo uso) y firma Ed25519
    /// de `ellkan_crypto::clave_privada::mensaje_reemplazo_clave_privada`
    /// sobre ese nonce y el blob nuevo — prueba de que quien lo sube tiene
    /// la identidad de la cuenta.
    pub challenge_nonce_b64: String,
    pub signature_b64: String,
}

#[derive(Debug, Serialize)]
pub struct SolicitudAdminResponse {
    pub id: Uuid,
    pub target_email: String,
    pub status: String,
    pub approvals_count: usize,
    pub approval_threshold: i32,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}
