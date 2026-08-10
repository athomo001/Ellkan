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
}

#[derive(Debug, Serialize)]
pub struct OrgPublicKeyResponse {
    pub public_key_x25519_b64: String,
}

#[derive(Debug, Deserialize)]
pub struct EnrolarRequest {
    pub sealed_private_key_for_org_b64: String,
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
pub struct CompletarSolicitudRequest {
    pub encrypted_private_key_blob_b64: String,
    pub private_key_nonce_b64: String,
    pub kdf_salt_b64: String,
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
