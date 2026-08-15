// Autor: Athan Espinoza

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct SharingPolicyResponse {
    pub restrict_visibility_by_group: bool,
}

#[derive(Debug, Deserialize)]
pub struct ActualizarSharingPolicyRequest {
    pub restrict_visibility_by_group: bool,
}
