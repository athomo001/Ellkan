// Autor: Athan Espinoza

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Serialize)]
pub struct ConfigResponse {
    pub ldap_url: Option<String>,
    pub bind_dn: Option<String>,
    pub require_starttls: bool,
    pub base_dn: Option<String>,
    pub user_filter: Option<String>,
    pub attribute_mapping: BTreeMap<String, String>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_sync_at: Option<OffsetDateTime>,
}

#[derive(Debug, Deserialize)]
pub struct ActualizarConfigRequest {
    pub ldap_url: Option<String>,
    pub bind_dn: Option<String>,
    #[serde(default)]
    pub bind_password: Option<String>,
    #[serde(default)]
    pub require_starttls: bool,
    pub base_dn: Option<String>,
    #[serde(default)]
    pub user_filter: Option<String>,
    #[serde(default)]
    pub attribute_mapping: BTreeMap<String, String>,
}
