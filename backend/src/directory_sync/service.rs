// Autor: Athan Espinoza

//! Service de Directory Sync LDAP (F-19) — nunca importa `axum`. TLS o
//! StartTLS es obligatorio: se valida el esquema/`require_starttls` antes
//! de siquiera intentar el bind, nunca después. El mapeo de atributos
//! nunca puede exponer credenciales del directorio (`userPassword` y
//! equivalentes), verificado en código, no confiado a la configuración.

use std::time::Duration;

use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use uuid::Uuid;

use crate::audit::models::{AuditEventType, EventoAuditoria};
use crate::error::DomainError;
use crate::eventos::{DomainEvent, EmisorDeEventos};
use crate::groups::models::GrupoDeUsuario;
use crate::groups::repository::{GroupMemberRepository, GroupRepository};
use crate::resources::repository::PermissionRepository;
use crate::scim::models::ResultadoCrearUsuario;
use crate::scim::repository::ScimUserRepository;
use ellkan_crypto::aead;
use ellkan_crypto::secretos::ClaveSecreta32;

use super::models::{CambioGrupoUsuario, DirectorySyncConfig, EntradaLdap, ResultadoSync, ATRIBUTOS_PROHIBIDOS};
use super::repository::DirectorySyncConfigRepository;

/// Resuelve el nombre de grupo desde un valor crudo de `memberOf` — si
/// tiene forma de DN (`cn=RRHH,ou=groups,dc=...`), extrae el valor del
/// primer RDN; si no, lo usa tal cual (atributo plano con nombres directos).
fn nombre_de_grupo_desde_valor_ldap(valor: &str) -> String {
    match valor.split_once('=') {
        Some((_, resto)) => resto.split(',').next().unwrap_or(resto).trim().to_string(),
        None => valor.trim().to_string(),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DirectorySyncError {
    #[error("directory sync no está configurado")]
    NoConfigurado,
    #[error("la conexión LDAP debe usar TLS o StartTLS — configurá ldaps:// o require_starttls=true")]
    TlsRequerido,
    #[error("el mapeo de atributos no puede incluir '{0}' — es una credencial del directorio, nunca un campo de usuario")]
    AtributoProhibido(String),
    #[error("error de conexión/búsqueda LDAP: {0}")]
    Ldap(String),
}

impl From<DirectorySyncError> for DomainError {
    fn from(e: DirectorySyncError) -> Self {
        match e {
            DirectorySyncError::AtributoProhibido(_) => DomainError::ValidacionInvalida(e.to_string()),
            _ => DomainError::ValidacionInvalida(e.to_string()),
        }
    }
}

/// RFC 4515 §3 — escapa los cuatro caracteres especiales de un filtro LDAP
/// antes de concatenarlo; un admin que configura un filtro custom nunca
/// puede alterar el alcance real de la query con metacaracteres sin
/// escapar (F-19, hallazgo real Passbolt PBL-09-001).
pub fn escapar_filtro_ldap(valor: &str) -> String {
    let mut salida = String::with_capacity(valor.len());
    for c in valor.chars() {
        match c {
            '\\' => salida.push_str("\\5c"),
            '*' => salida.push_str("\\2a"),
            '(' => salida.push_str("\\28"),
            ')' => salida.push_str("\\29"),
            '\0' => salida.push_str("\\00"),
            _ => salida.push(c),
        }
    }
    salida
}

fn validar_mapeo(mapping: &std::collections::BTreeMap<String, String>) -> Result<(), DirectorySyncError> {
    for atributo in mapping.values() {
        if ATRIBUTOS_PROHIBIDOS.contains(&atributo.to_lowercase().as_str()) {
            return Err(DirectorySyncError::AtributoProhibido(atributo.clone()));
        }
    }
    Ok(())
}

fn validar_tls(cfg: &DirectorySyncConfig) -> Result<(), DirectorySyncError> {
    let url = cfg.ldap_url.as_deref().ok_or(DirectorySyncError::NoConfigurado)?;
    if url.starts_with("ldaps://") {
        return Ok(());
    }
    if url.starts_with("ldap://") && cfg.require_starttls {
        return Ok(());
    }
    Err(DirectorySyncError::TlsRequerido)
}

pub struct DirectorySyncService<'a, C, U, GR, GM, P> {
    pub config: &'a C,
    pub usuarios: &'a U,
    /// F-19: sólo se usan si `sync_groups` está activo — find-or-create de
    /// grupos raíz (`GR`) y reconciliación de membresía (`GM`); `P` resuelve
    /// qué recursos comparte un grupo al reconciliar una baja, mismo
    /// criterio que `GroupService::quitar_miembro`.
    pub grupos: &'a GR,
    pub miembros: &'a GM,
    pub permisos: &'a P,
    pub secrets_key: &'a ClaveSecreta32,
    pub eventos: EmisorDeEventos,
}

impl<'a, C, U, GR, GM, P> DirectorySyncService<'a, C, U, GR, GM, P>
where
    C: DirectorySyncConfigRepository,
    U: ScimUserRepository,
    GR: GroupRepository,
    GM: GroupMemberRepository,
    P: PermissionRepository,
{
    pub async fn config(&self) -> Result<DirectorySyncConfig, DomainError> {
        Ok(self.config.obtener().await?)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn actualizar_config(
        &self,
        actor_id: Uuid,
        ldap_url: Option<String>,
        bind_dn: Option<String>,
        bind_password: Option<String>,
        require_starttls: bool,
        base_dn: Option<String>,
        user_filter: Option<String>,
        attribute_mapping: std::collections::BTreeMap<String, String>,
        user_object_class: String,
        sync_groups: bool,
        group_membership_attribute: String,
    ) -> Result<DirectorySyncConfig, DomainError> {
        validar_mapeo(&attribute_mapping)?;
        if user_object_class.trim().is_empty() {
            return Err(DomainError::ValidacionInvalida("user_object_class no puede estar vacío".into()));
        }
        if group_membership_attribute.trim().is_empty() {
            return Err(DomainError::ValidacionInvalida("group_membership_attribute no puede estar vacío".into()));
        }

        let (cifrado, nonce) = match bind_password {
            Some(pw) => {
                let envoltura =
                    aead::cifrar(self.secrets_key, pw.as_bytes(), b"directory_sync_bind_password")
                        .expect("cifrar no falla");
                (Some(envoltura.ciphertext), Some(envoltura.nonce.to_vec()))
            }
            None => (None, None),
        };

        let mapping_json = serde_json::to_value(&attribute_mapping).expect("serializar mapping no falla");
        self.config
            .actualizar(
                ldap_url.as_deref(),
                bind_dn.as_deref(),
                cifrado.as_deref(),
                nonce.as_deref(),
                require_starttls,
                base_dn.as_deref(),
                user_filter.as_deref(),
                &mapping_json,
                &user_object_class,
                sync_groups,
                &group_membership_attribute,
            )
            .await?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::DirectorySyncConfigUpdated, Some(actor_id)),
        ));

        self.config().await
    }

    async fn buscar_entradas(&self, cfg: &DirectorySyncConfig) -> Result<Vec<EntradaLdap>, DomainError> {
        validar_tls(cfg)?;
        validar_mapeo(&cfg.attribute_mapping)?;

        let url = cfg.ldap_url.as_deref().ok_or(DirectorySyncError::NoConfigurado)?;
        let base_dn = cfg.base_dn.as_deref().ok_or(DirectorySyncError::NoConfigurado)?;
        let bind_dn = cfg.bind_dn.as_deref().ok_or(DirectorySyncError::NoConfigurado)?;

        let (cifrado, nonce) = self
            .config
            .obtener_credencial_bind()
            .await?
            .ok_or(DirectorySyncError::NoConfigurado)?;
        let nonce: [u8; 24] = nonce.try_into().map_err(|_| DirectorySyncError::NoConfigurado)?;
        let envoltura = aead::Envoltura { nonce, ciphertext: cifrado };
        let bind_password_bytes = aead::descifrar(self.secrets_key, &envoltura, b"directory_sync_bind_password")
            .map_err(|_| DirectorySyncError::Ldap("no se pudo descifrar la credencial de bind".into()))?;
        let bind_password =
            String::from_utf8(bind_password_bytes).map_err(|_| DirectorySyncError::Ldap("credencial inválida".into()))?;

        let settings = LdapConnSettings::new()
            .set_starttls(url.starts_with("ldap://"))
            .set_conn_timeout(Duration::from_secs(10))
            // Sólo para el LDAP de prueba de esta fase (certificado
            // autofirmado) — producción necesita un certificado válido.
            .set_no_tls_verify(std::env::var("ELLKAN_DIRECTORY_SYNC_INSECURE_TLS").is_ok());

        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, url)
            .await
            .map_err(|e| DirectorySyncError::Ldap(e.to_string()))?;
        ldap3::drive!(conn);

        ldap.simple_bind(bind_dn, &bind_password)
            .await
            .and_then(|r| r.success())
            .map_err(|e| DirectorySyncError::Ldap(e.to_string()))?;

        let filtro_base = format!("(objectClass={})", escapar_filtro_ldap(&cfg.user_object_class));
        let filtro = match &cfg.user_filter {
            Some(custom) if !custom.is_empty() => {
                format!("(&{filtro_base}({}))", escapar_filtro_ldap(custom))
            }
            _ => filtro_base,
        };

        let campo_external_id = cfg.attribute_mapping.get("external_id").cloned().unwrap_or_else(|| "uid".into());
        let campo_email = cfg.attribute_mapping.get("email").cloned().unwrap_or_else(|| "mail".into());
        let campo_nombre = cfg.attribute_mapping.get("display_name").cloned().unwrap_or_else(|| "cn".into());

        let mut atributos = vec![campo_external_id.as_str(), campo_email.as_str(), campo_nombre.as_str()];
        if cfg.sync_groups {
            atributos.push(cfg.group_membership_attribute.as_str());
        }

        let (resultados, _res) = ldap
            .search(base_dn, Scope::Subtree, &filtro, atributos)
            .await
            .map_err(|e| DirectorySyncError::Ldap(e.to_string()))?
            .success()
            .map_err(|e| DirectorySyncError::Ldap(e.to_string()))?;

        let _ = ldap.unbind().await;

        let mut entradas = Vec::new();
        for r in resultados {
            let se = SearchEntry::construct(r);
            let external_id = se.attrs.get(&campo_external_id).and_then(|v| v.first()).cloned();
            let email = se.attrs.get(&campo_email).and_then(|v| v.first()).cloned();
            let nombre = se.attrs.get(&campo_nombre).and_then(|v| v.first()).cloned();
            let grupos = if cfg.sync_groups {
                se.attrs
                    .get(&cfg.group_membership_attribute)
                    .map(|valores| valores.iter().map(|v| nombre_de_grupo_desde_valor_ldap(v)).collect())
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
            if let (Some(external_id), Some(email)) = (external_id, email) {
                entradas.push(EntradaLdap { external_id, email, display_name: nombre.unwrap_or_default(), grupos });
            }
        }

        Ok(entradas)
    }

    /// Calcula el diff sin aplicar nada — usado tanto por dry-run (persiste
    /// el resultado, no toca `users`) como por `apply` (mismo cálculo,
    /// después sí muta).
    async fn calcular_diff(&self, cfg: &DirectorySyncConfig, entradas: &[EntradaLdap]) -> Result<ResultadoSync, DomainError> {
        let mut resultado = ResultadoSync::default();

        for entrada in entradas {
            let existente = self.usuarios.buscar_por_external_id(&entrada.external_id).await?;
            match &existente {
                Some(u) if u.active => resultado.unchanged += 1,
                Some(_) => resultado.would_reactivate.push(entrada.external_id.clone()),
                None => match self.usuarios.buscar_por_email(&entrada.email).await? {
                    Some(otro) if otro.external_id.as_deref() != Some(entrada.external_id.as_str()) => {
                        resultado.conflicts.push(entrada.email.clone())
                    }
                    _ => resultado.would_create.push(entrada.external_id.clone()),
                },
            }

            if cfg.sync_groups {
                let deseados: std::collections::HashSet<&str> = entrada.grupos.iter().map(String::as_str).collect();
                let actuales: Vec<GrupoDeUsuario> = match &existente {
                    Some(u) => self.miembros.grupos_gestionados_de(u.id).await?,
                    None => Vec::new(),
                };
                let nombres_actuales: std::collections::HashSet<&str> = actuales.iter().map(|g| g.name.as_str()).collect();

                let nuevos: Vec<String> = deseados.difference(&nombres_actuales).map(|s| s.to_string()).collect();
                let removidos: Vec<String> = nombres_actuales.difference(&deseados).map(|s| s.to_string()).collect();
                if !nuevos.is_empty() || !removidos.is_empty() {
                    resultado.group_changes.push(CambioGrupoUsuario {
                        external_id: entrada.external_id.clone(),
                        grupos_nuevos: nuevos,
                        grupos_removidos: removidos,
                    });
                }
            }
        }

        // Usuarios gestionados por directory sync que ya no aparecen en el
        // LDAP — se desactivan, nunca se borran (F-19, mismo criterio que
        // SCIM F-18).
        let (gestionados, _total) = self.usuarios.listar(0, 10_000).await?;
        let ids_ldap: std::collections::HashSet<&str> =
            entradas.iter().map(|e| e.external_id.as_str()).collect();
        for u in gestionados {
            if u.active
                && let Some(ext) = &u.external_id
                && !ids_ldap.contains(ext.as_str())
            {
                resultado.would_deactivate.push(ext.clone());
            }
        }

        Ok(resultado)
    }

    pub async fn dry_run(&self, actor_id: Uuid) -> Result<ResultadoSync, DomainError> {
        let cfg = self.config().await?;
        let entradas = self.buscar_entradas(&cfg).await?;
        let resultado = self.calcular_diff(&cfg, &entradas).await?;

        let json = serde_json::to_value(&resultado).expect("serializar resultado no falla");
        self.config.guardar_resultado_dry_run(&json).await?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::DirectorySyncDryRun, Some(actor_id)),
        ));

        Ok(resultado)
    }

    pub async fn aplicar(&self, actor_id: Uuid) -> Result<ResultadoSync, DomainError> {
        let cfg = self.config().await?;
        let entradas = self.buscar_entradas(&cfg).await?;
        let resultado = self.calcular_diff(&cfg, &entradas).await?;

        for entrada in &entradas {
            match self.usuarios.buscar_por_external_id(&entrada.external_id).await? {
                Some(existente) if !existente.active => {
                    self.usuarios.actualizar_activo(existente.id, true).await?;
                }
                Some(_) => {}
                None => {
                    let scim = crate::scim::service::ScimService { usuarios: self.usuarios, eventos: self.eventos.clone() };
                    let resultado_alta =
                        scim.crear_usuario(&entrada.external_id, &entrada.email, &entrada.display_name).await?;
                    // `ConflictoDeEmail` ya quedó contabilizado en
                    // `resultado.conflicts` por `calcular_diff` — no se
                    // toca esa cuenta acá.
                    let _ = matches!(resultado_alta, ResultadoCrearUsuario::ConflictoDeEmail);
                }
            }
        }

        for external_id in &resultado.would_deactivate {
            if let Some(u) = self.usuarios.buscar_por_external_id(external_id).await? {
                self.usuarios.actualizar_activo(u.id, false).await?;
            }
        }

        // F-19: reconciliación de grupos — corre después de alta/reactivación
        // (todo usuario de `entradas` ya existe en este punto). Alta: cada
        // nombre de `entrada.grupos` se resuelve a un grupo raíz gestionado
        // (find-or-create) y se agrega la membresía (idempotente, un
        // `Conflict` significa que ya era miembro). Baja: cualquier grupo
        // gestionado al que el usuario pertenecía y ya no aparece en su
        // `memberOf` actual se revoca, junto con el acceso a los recursos
        // que ese grupo comparte (mismo criterio que `GroupService::quitar_miembro`).
        if cfg.sync_groups {
            for entrada in &entradas {
                let Some(usuario) = self.usuarios.buscar_por_external_id(&entrada.external_id).await? else {
                    continue;
                };

                for nombre_grupo in &entrada.grupos {
                    let group_id = self.grupos.buscar_o_crear_raiz_gestionado(nombre_grupo).await?;
                    if let Err(e) = self.miembros.agregar_simple(group_id, usuario.id, false).await
                        && !matches!(e, crate::error::RepoError::Conflict)
                    {
                        return Err(e.into());
                    }
                }

                let deseados: std::collections::HashSet<&str> = entrada.grupos.iter().map(String::as_str).collect();
                for actual in self.miembros.grupos_gestionados_de(usuario.id).await? {
                    if !deseados.contains(actual.name.as_str()) {
                        let recursos_compartidos = self.permisos.recursos_por_grantee("group", actual.group_id).await?;
                        self.miembros.quitar(actual.group_id, usuario.id, &recursos_compartidos).await?;
                    }
                }
            }
        }

        self.config.marcar_sync_aplicado().await?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::DirectorySyncApplied, Some(actor_id)),
        ));

        Ok(resultado)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapa_los_cuatro_metacaracteres_de_rfc_4515() {
        assert_eq!(escapar_filtro_ldap("a*b"), "a\\2ab");
        assert_eq!(escapar_filtro_ldap("(uid=x)"), "\\28uid=x\\29");
        assert_eq!(escapar_filtro_ldap("back\\slash"), "back\\5cslash");
        assert_eq!(escapar_filtro_ldap("normal"), "normal");
    }

    #[test]
    fn filtro_con_metacaracteres_no_altera_el_alcance_de_la_query() {
        // Un intento de "escapar" el filtro base concatenando `)(uid=*` no
        // debe cerrar el grupo del filtro real — queda como texto literal
        // dentro del valor buscado.
        let intento_de_inyeccion = ")(uid=*";
        let escapado = escapar_filtro_ldap(intento_de_inyeccion);
        assert!(!escapado.contains(')'), "el paréntesis de cierre debe quedar escapado, no crudo");
        assert!(!escapado.contains('('), "el paréntesis de apertura debe quedar escapado, no crudo");
    }

    #[test]
    fn mapear_userpassword_falla_explicito() {
        let mut mapping = std::collections::BTreeMap::new();
        mapping.insert("external_id".to_string(), "uid".to_string());
        mapping.insert("email".to_string(), "userPassword".to_string());
        assert!(validar_mapeo(&mapping).is_err(), "mapear userPassword debe fallar aunque venga de un admin");
    }
}
