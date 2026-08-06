// Autor: Athan Espinoza

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct RetentionPolicyResponse {
    pub data_retention_days: i32,
    pub audit_log_retention_days: i32,
}

#[derive(Debug, Deserialize)]
pub struct ActualizarRetentionPolicyRequest {
    pub data_retention_days: i32,
    pub audit_log_retention_days: i32,
}
