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
    pub user_object_class: String,
    pub sync_groups: bool,
    pub group_membership_attribute: String,
    pub directory_unreachable_policy: String,
    pub grace_seconds: i32,
    pub session_revalidate_seconds: i32,
    pub auto_sync_enabled: bool,
    pub poll_interval_seconds: i32,
    pub max_deactivations_per_run: Option<i32>,
    pub last_auto_sync_error: Option<String>,
}

fn default_user_object_class() -> String {
    "inetOrgPerson".to_string()
}

fn default_group_membership_attribute() -> String {
    "memberOf".to_string()
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
    #[serde(default = "default_user_object_class")]
    pub user_object_class: String,
    #[serde(default)]
    pub sync_groups: bool,
    #[serde(default = "default_group_membership_attribute")]
    pub group_membership_attribute: String,
    /// spec/15 §3.2 (#52). Ausentes = se dejan como estaban.
    #[serde(default)]
    pub directory_unreachable_policy: Option<String>,
    #[serde(default)]
    pub grace_seconds: Option<i32>,
    #[serde(default)]
    pub session_revalidate_seconds: Option<i32>,
    /// spec/15 §2 (#53). Ausentes = sin cambio. `max_deactivations_per_run`
    /// en `0` = automático (10 %, mínimo 5).
    #[serde(default)]
    pub auto_sync_enabled: Option<bool>,
    #[serde(default)]
    pub poll_interval_seconds: Option<i32>,
    #[serde(default)]
    pub max_deactivations_per_run: Option<i32>,
}

/// `POST /admin/directory-sync/apply?confirm_mass_deactivation=true` (§2.5).
#[derive(Debug, Deserialize, Default)]
pub struct AplicarQuery {
    #[serde(default)]
    pub confirm_mass_deactivation: bool,
}
