// Autor: Athan Espinoza

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct SelfRegistrationPolicyResponse {
    pub enabled: bool,
    pub allowed_domains: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ActualizarSelfRegistrationPolicyRequest {
    pub enabled: bool,
    pub allowed_domains: Vec<String>,
}
