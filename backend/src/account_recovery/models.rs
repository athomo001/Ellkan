// Autor: Athan Espinoza

use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct AccountRecoveryPolicy {
    pub required: bool,
    pub grace_period_days: i32,
    pub default_approval_threshold: i32,
}

#[derive(Debug, Clone)]
pub struct OrgRecoveryKey {
    pub id: i32,
    pub public_key_x25519: Vec<u8>,
    pub encrypted_private_key: Vec<u8>,
    pub private_key_nonce: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Escrow {
    pub id: Uuid,
    pub user_id: Uuid,
    pub sealed_private_key_for_org: Vec<u8>,
    pub org_recovery_key_id: i32,
    pub approval_threshold: i32,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct RecoveryRequest {
    pub id: Uuid,
    pub escrow_id: Uuid,
    pub requested_by: Option<Uuid>,
    pub status: String,
    pub approvals: Value,
    pub requester_public_key_x25519: Vec<u8>,
    pub sealed_private_key_for_requester: Option<Vec<u8>>,
    pub created_at: OffsetDateTime,
}
