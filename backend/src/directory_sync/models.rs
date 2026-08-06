// Autor: Athan Espinoza

use time::OffsetDateTime;

#[derive(Debug, Clone, Default)]
pub struct DirectorySyncConfig {
    pub ldap_url: Option<String>,
    pub bind_dn: Option<String>,
    /// Sólo se acepta al guardar (`PUT`) — nunca se devuelve en la
    /// respuesta (mismo criterio que cualquier credencial de servicio).
    pub bind_password: Option<String>,
    pub require_starttls: bool,
    pub base_dn: Option<String>,
    pub user_filter: Option<String>,
    pub attribute_mapping: std::collections::BTreeMap<String, String>,
    pub last_sync_at: Option<OffsetDateTime>,
}

/// Atributos LDAP que ningún mapeo puede exponer — ni siquiera configurado
/// explícitamente por un admin (F-19, hallazgo real Passbolt PBL-09-002).
pub const ATRIBUTOS_PROHIBIDOS: &[&str] = &["userpassword", "unicodepwd", "sambantpassword", "krbprincipalkey"];

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ResultadoSync {
    pub would_create: Vec<String>,
    pub would_reactivate: Vec<String>,
    pub would_deactivate: Vec<String>,
    pub unchanged: usize,
    pub conflicts: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct EntradaLdap {
    pub external_id: String,
    pub email: String,
    pub display_name: String,
}
