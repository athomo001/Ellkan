// Autor: Athan Espinoza

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use super::models::{ScimTokenRow, ScimUser};

#[derive(Debug, Serialize)]
pub struct ScimUserResponse {
    pub schemas: Vec<String>,
    pub id: Uuid,
    #[serde(rename = "externalId", skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    #[serde(rename = "userName")]
    pub user_name: String,
    pub active: bool,
    pub emails: Vec<ScimEmail>,
}

#[derive(Debug, Serialize)]
pub struct ScimEmail {
    pub value: String,
    pub primary: bool,
}

impl From<ScimUser> for ScimUserResponse {
    fn from(u: ScimUser) -> Self {
        Self {
            schemas: vec!["urn:ietf:params:scim:schemas:core:2.0:User".to_string()],
            id: u.id,
            external_id: u.external_id,
            user_name: u.email.clone(),
            active: u.active,
            emails: vec![ScimEmail { value: u.email, primary: true }],
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CrearScimUserRequest {
    #[serde(rename = "externalId")]
    pub external_id: String,
    #[serde(rename = "userName")]
    pub user_name: String,
    #[serde(default)]
    pub emails: Vec<ScimEmailInput>,
    #[serde(rename = "displayName", default)]
    pub display_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ScimEmailInput {
    pub value: String,
}

impl CrearScimUserRequest {
    pub fn email(&self) -> String {
        self.emails.first().map(|e| e.value.clone()).unwrap_or_else(|| self.user_name.clone())
    }

    pub fn nombre(&self) -> String {
        self.display_name.clone().unwrap_or_else(|| self.user_name.clone())
    }
}

#[derive(Debug, Deserialize)]
pub struct ListarScimQuery {
    #[serde(rename = "startIndex", default = "default_start_index")]
    pub start_index: i64,
    #[serde(default = "default_count")]
    pub count: i64,
}

fn default_start_index() -> i64 {
    1
}
fn default_count() -> i64 {
    100
}

#[derive(Debug, Serialize)]
pub struct ScimListResponse {
    pub schemas: Vec<String>,
    #[serde(rename = "totalResults")]
    pub total_results: i64,
    #[serde(rename = "startIndex")]
    pub start_index: i64,
    #[serde(rename = "itemsPerPage")]
    pub items_per_page: i64,
    #[serde(rename = "Resources")]
    pub resources: Vec<ScimUserResponse>,
}

#[derive(Debug, Deserialize)]
pub struct PatchScimUserRequest {
    #[serde(rename = "Operations")]
    pub operations: Vec<PatchOperation>,
}

#[derive(Debug, Deserialize)]
pub struct PatchOperation {
    pub op: String,
    pub path: Option<String>,
    pub value: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct ScimErrorResponse {
    pub schemas: Vec<String>,
    pub status: String,
    pub detail: String,
}

impl ScimErrorResponse {
    pub fn new(status: u16, detail: impl Into<String>) -> Self {
        Self {
            schemas: vec!["urn:ietf:params:scim:api:messages:2.0:Error".to_string()],
            status: status.to_string(),
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ScimTokenResponse {
    pub token: String,
}

/// H-08: listado de tokens SCIM existentes, sin el token en claro ni su
/// hash — sólo lo necesario para que un admin elija cuál revocar.
#[derive(Debug, Serialize)]
pub struct ScimTokenRowResponse {
    pub id: Uuid,
    pub created_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
}

impl From<ScimTokenRow> for ScimTokenRowResponse {
    fn from(fila: ScimTokenRow) -> Self {
        Self { id: fila.id, created_at: fila.created_at, revoked_at: fila.revoked_at }
    }
}
