// Autor: Athan Espinoza

use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct EmergencyAccess {
    pub id: Uuid,
    pub granter_id: Uuid,
    pub grantee_id: Uuid,
    pub access_level: String,
    pub sealed_material: Vec<u8>,
    pub wait_time_days: i32,
    pub status: String,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct EmergencyAccessRequest {
    pub id: Uuid,
    pub emergency_access_id: Uuid,
    pub requested_at: OffsetDateTime,
    pub status: String,
    pub resolved_at: Option<OffsetDateTime>,
}
