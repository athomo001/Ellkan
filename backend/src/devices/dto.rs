// Autor: Athan Espinoza

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct MarcarConfiableRequest {
    pub device_public_key_b64: String,
    pub sealed_user_private_key_b64: String,
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TrustedDeviceResponse {
    pub id: Uuid,
    pub label: Option<String>,
    pub created_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
}

#[derive(Debug, Deserialize)]
pub struct SolicitarAprobacionRequest {
    pub email: String,
    pub device_public_key_b64: String,
}

#[derive(Debug, Serialize)]
pub struct ApprovalRequestResponse {
    pub id: Uuid,
    pub fingerprint: String,
    pub status: String,
    /// Sólo presentes una vez `status == "approved"`.
    pub session_id: Option<Uuid>,
    pub sealed_user_private_key_b64: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AprobarRequest {
    pub sealed_user_private_key_b64: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceApprovalPolicyResponse {
    pub allow_peer_device_approval: bool,
    pub allow_admin_device_approval: bool,
}
