// Autor: Athan Espinoza

use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct TrustedDevice {
    pub id: Uuid,
    pub user_id: Uuid,
    pub device_public_key: Vec<u8>,
    pub label: Option<String>,
    pub created_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
}

#[derive(Debug, Clone)]
pub struct ApprovalRequest {
    pub id: Uuid,
    pub user_id: Uuid,
    pub device_public_key: Vec<u8>,
    pub fingerprint: String,
    pub status: String,
    pub sealed_user_private_key: Option<Vec<u8>>,
    pub session_id: Option<Uuid>,
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct DeviceApprovalPolicy {
    pub allow_peer_device_approval: bool,
    pub allow_admin_device_approval: bool,
}
