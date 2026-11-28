// Autor: Athan Espinoza

use time::OffsetDateTime;

#[derive(Debug, Clone)]
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
    /// Reemplaza el `objectClass` hardcodeado del filtro base — default
    /// `inetOrgPerson` (OpenLDAP); Active Directory usa `user`.
    pub user_object_class: String,
    /// `false` por default — instalaciones ya configuradas no empiezan a
    /// crear grupos de golpe sin que un admin lo prenda a propósito.
    pub sync_groups: bool,
    /// Atributo multivaluado en la propia entrada de usuario (default
    /// `memberOf`, estilo Active Directory — funciona igual en OpenLDAP con
    /// el overlay `memberof` activado).
    pub group_membership_attribute: String,
    /// spec/15 §3.2 (#52): `grace` o `deny` si el directorio no responde.
    pub directory_unreachable_policy: String,
    pub grace_seconds: i32,
    /// spec/15 §3.1: cada cuánto se re-verifica una sesión abierta.
    pub session_revalidate_seconds: i32,
    /// spec/15 §2 (#53): el servidor corre el «aplicar» solo cada
    /// `poll_interval_seconds`.
    pub auto_sync_enabled: bool,
    pub poll_interval_seconds: i32,
    /// §2.5: tope de bajas por corrida; `None` = 10 % de las gestionadas
    /// activas, mínimo 5.
    pub max_deactivations_per_run: Option<i32>,
    pub last_auto_sync_error: Option<String>,
}

impl DirectorySyncConfig {
    /// §2.5: cuántas bajas se aceptan en una corrida sin confirmación.
    pub fn tope_de_bajas(&self, gestionadas_activas: usize) -> usize {
        match self.max_deactivations_per_run {
            Some(n) => n.max(1) as usize,
            None => (gestionadas_activas / 10).max(5),
        }
    }
}

impl Default for DirectorySyncConfig {
    fn default() -> Self {
        Self {
            ldap_url: None,
            bind_dn: None,
            bind_password: None,
            require_starttls: false,
            base_dn: None,
            user_filter: None,
            attribute_mapping: Default::default(),
            last_sync_at: None,
            user_object_class: "inetOrgPerson".to_string(),
            sync_groups: false,
            group_membership_attribute: "memberOf".to_string(),
            directory_unreachable_policy: "grace".to_string(),
            grace_seconds: 900,
            session_revalidate_seconds: 300,
            auto_sync_enabled: false,
            poll_interval_seconds: 60,
            max_deactivations_per_run: None,
            last_auto_sync_error: None,
        }
    }
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
    /// Vacío si `sync_groups=false` — un ítem por usuario con al menos un
    /// cambio de membresía (alta o baja) en un grupo gestionado.
    pub group_changes: Vec<CambioGrupoUsuario>,
    /// spec/15 §2.5 (#53): la corrida desactivaría más de lo permitido (o
    /// el directorio devolvió 0 usuarios con cuentas gestionadas): `aplicar`
    /// no hace nada salvo que un admin lo confirme.
    pub requires_confirmation: bool,
    /// `true` si `aplicar` se abortó por eso.
    pub aborted: bool,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct CambioGrupoUsuario {
    pub external_id: String,
    pub grupos_nuevos: Vec<String>,
    pub grupos_removidos: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct EntradaLdap {
    pub external_id: String,
    pub email: String,
    pub display_name: String,
    /// Nombres de grupo ya resueltos (DN → primer RDN si hacía falta) —
    /// vacío si `sync_groups=false`.
    pub grupos: Vec<String>,
}
