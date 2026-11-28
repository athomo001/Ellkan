// Autor: Athan Espinoza

//! spec/15 §3 (pendiente #52): verificación puntual contra el directorio
//! LDAP en el login y, cada `session_revalidate_seconds`, en las sesiones
//! abiertas. Garantiza que una cuenta borrada o deshabilitada en AD no entre
//! aunque el sync no haya corrido.
//!
//! Sólo para cuentas con `users.managed_by = 'directory_sync'`. Las locales
//! (admins de emergencia, §3.3) y las de SCIM no pasan por acá.
//!
//! - Vigente → se anota `last_directory_check_at`.
//! - Baja (no existe en el alcance, `ACCOUNTDISABLE`, expirada o bloqueada
//!   por ppolicy) → se aplica la baja en el momento (`active = false` +
//!   rota `security_stamp`, que corta todas sus sesiones), se audita con el
//!   motivo y se rechaza con el error genérico de credenciales.
//! - El directorio no responde → `grace`: entra sólo si la última
//!   verificación buena de ese usuario tiene menos de `grace_seconds`;
//!   `deny`: no entra. No existe «permitir sin límite» (§3.2).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ldap3::{Scope, SearchEntry};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::audit::models::{AuditEventType, EventoAuditoria};
use crate::error::DomainError;
use crate::eventos::{DomainEvent, EmisorDeEventos};
use ellkan_crypto::secretos::ClaveSecreta32;

use super::models::DirectorySyncConfig;
use super::repository::{DirectorySyncConfigRepository, PgDirectorySyncConfigRepository};
use super::service::{conectar_ldap, escapar_filtro_ldap, filtro_de_usuarios};

/// Resultado de mirar una cuenta en el directorio.
#[derive(Debug, PartialEq, Eq)]
pub enum EstadoEnDirectorio {
    Vigente,
    /// Con el motivo de `spec/15 §2.3` (`deactivated_reason`).
    Baja(&'static str),
}

/// `accountExpires` de AD: FILETIME (100 ns desde 1601-01-01 UTC). `0` y
/// `0x7FFFFFFFFFFFFFFF` = no vence.
fn expirada_ad(valor: &str, ahora: OffsetDateTime) -> bool {
    let Ok(ft) = valor.trim().parse::<i64>() else { return false };
    if ft == 0 || ft == i64::MAX {
        return false;
    }
    const SEGUNDOS_1601_A_1970: i64 = 11_644_473_600;
    let unix = ft / 10_000_000 - SEGUNDOS_1601_A_1970;
    unix < ahora.unix_timestamp()
}

/// Decide con los atributos de la entrada (ya encontrada en el alcance).
pub fn estado_de_entrada(attrs: &HashMap<String, Vec<String>>, ahora: OffsetDateTime) -> EstadoEnDirectorio {
    let primero = |nombre: &str| {
        attrs
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(nombre))
            .and_then(|(_, v)| v.first())
            .map(String::as_str)
    };
    // AD: bit 0x2 (ACCOUNTDISABLE) de userAccountControl.
    if let Some(uac) = primero("userAccountControl").and_then(|v| v.trim().parse::<u32>().ok())
        && uac & 0x2 != 0
    {
        return EstadoEnDirectorio::Baja("directory_disabled");
    }
    if primero("accountExpires").is_some_and(|v| expirada_ad(v, ahora)) {
        return EstadoEnDirectorio::Baja("directory_expired");
    }
    // OpenLDAP (overlay ppolicy): cuenta bloqueada.
    if primero("pwdAccountLockedTime").is_some() {
        return EstadoEnDirectorio::Baja("directory_disabled");
    }
    EstadoEnDirectorio::Vigente
}

#[derive(Clone)]
pub struct VerificadorDirectorio {
    pool: sqlx::PgPool,
    config: PgDirectorySyncConfigRepository,
    secrets_key: Arc<ClaveSecreta32>,
    eventos: EmisorDeEventos,
    /// Última verificación hecha por este proceso, para no ir al directorio
    /// en cada request (§3.1: «se cachea por usuario durante esa ventana»).
    recientes: Arc<Mutex<HashMap<Uuid, Instant>>>,
}

struct Cuenta {
    managed_by: Option<String>,
    external_id: Option<String>,
    last_directory_check_at: Option<OffsetDateTime>,
}

impl VerificadorDirectorio {
    pub fn nuevo(pool: sqlx::PgPool, secrets_key: Arc<ClaveSecreta32>, eventos: EmisorDeEventos) -> Self {
        Self {
            config: PgDirectorySyncConfigRepository { pool: pool.clone() },
            pool,
            secrets_key,
            eventos,
            recientes: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Login (`POST /auth/verify`): verifica siempre, sin caché.
    pub async fn exigir_vigente(&self, user_id: Uuid) -> Result<(), DomainError> {
        self.verificar(user_id, None).await
    }

    /// Sesión abierta: re-verifica si la última de este proceso tiene más
    /// de `session_revalidate_seconds`. Barato en el caso común (un mapa en
    /// memoria; a lo sumo una consulta a la base por usuario y ventana).
    pub async fn revalidar(&self, user_id: Uuid) -> Result<(), DomainError> {
        let ventana_minima = Duration::from_secs(30);
        if let Some(ultima) = self.recientes.lock().expect("mutex sano").get(&user_id)
            && ultima.elapsed() < ventana_minima
        {
            return Ok(());
        }
        self.verificar(user_id, Some(())).await
    }

    async fn verificar(&self, user_id: Uuid, revalidacion: Option<()>) -> Result<(), DomainError> {
        let fila = sqlx::query_as!(
            Cuenta,
            r#"select managed_by, external_id, last_directory_check_at from users where id = $1"#,
            user_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| DomainError::Interno(e.into()))?;
        let Some(cuenta) = fila else { return Ok(()) };
        let (Some("directory_sync"), Some(external_id)) = (cuenta.managed_by.as_deref(), cuenta.external_id.as_deref()) else {
            // No gestionada por el directorio: no hay nada que verificar.
            // Se anota igual para no volver a la base en cada request.
            self.anotar(user_id);
            return Ok(());
        };

        let cfg = self.config.obtener().await?;
        if cfg.ldap_url.is_none() {
            // El admin quitó la configuración de LDAP: no hay contra qué
            // verificar (el sync tampoco corre).
            self.anotar(user_id);
            return Ok(());
        }
        if revalidacion.is_some() {
            let ventana = Duration::from_secs(cfg.session_revalidate_seconds.max(30) as u64);
            if let Some(ultima) = self.recientes.lock().expect("mutex sano").get(&user_id)
                && ultima.elapsed() < ventana
            {
                return Ok(());
            }
        }

        match self.consultar(&cfg, external_id).await {
            Ok(EstadoEnDirectorio::Vigente) => {
                sqlx::query!(r#"update users set last_directory_check_at = now() where id = $1"#, user_id)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| DomainError::Interno(e.into()))?;
                self.anotar(user_id);
                Ok(())
            }
            Ok(EstadoEnDirectorio::Baja(motivo)) => {
                self.dar_de_baja(user_id, motivo).await;
                Err(DomainError::InvalidCredentials)
            }
            Err(e) => {
                let reciente = cuenta
                    .last_directory_check_at
                    .is_some_and(|t| (OffsetDateTime::now_utc() - t).whole_seconds() < i64::from(cfg.grace_seconds));
                if cfg.directory_unreachable_policy == "grace" && reciente {
                    tracing::warn!(%user_id, error = %e, "directorio sin respuesta: entra por la gracia de la última verificación");
                    Ok(())
                } else {
                    tracing::warn!(%user_id, error = %e, politica = %cfg.directory_unreachable_policy, "directorio sin respuesta: acceso rechazado");
                    Err(DomainError::InvalidCredentials)
                }
            }
        }
    }

    fn anotar(&self, user_id: Uuid) {
        self.recientes.lock().expect("mutex sano").insert(user_id, Instant::now());
    }

    /// Búsqueda puntual por el identificador estable, sólo de ese objeto.
    async fn consultar(&self, cfg: &DirectorySyncConfig, external_id: &str) -> Result<EstadoEnDirectorio, String> {
        let base_dn = cfg.base_dn.as_deref().ok_or("sin base DN")?;
        let credencial = self
            .config
            .obtener_credencial_bind()
            .await
            .map_err(|e| e.to_string())?
            .ok_or("sin credencial de bind")?;
        let mut ldap = conectar_ldap(cfg, credencial, &self.secrets_key).await.map_err(|e| e.to_string())?;
        let campo = cfg.attribute_mapping.get("external_id").cloned().unwrap_or_else(|| "uid".into());
        let filtro = format!(
            "(&{}({}={}))",
            filtro_de_usuarios(cfg),
            escapar_filtro_ldap(&campo),
            escapar_filtro_ldap(external_id)
        );
        let resultado = ldap
            .search(
                base_dn,
                Scope::Subtree,
                &filtro,
                vec!["userAccountControl", "accountExpires", "pwdAccountLockedTime"],
            )
            .await
            .map_err(|e| e.to_string())?
            .success();
        let _ = ldap.unbind().await;
        let (entradas, _) = match resultado {
            Ok(r) => r,
            // 32 = noSuchObject: el base DN ya no existe. Eso es config rota,
            // no una baja del usuario: se trata como «no responde».
            Err(e) => return Err(e.to_string()),
        };
        Ok(match entradas.into_iter().next() {
            None => EstadoEnDirectorio::Baja("directory_deleted"),
            Some(e) => estado_de_entrada(&SearchEntry::construct(e).attrs, OffsetDateTime::now_utc()),
        })
    }

    /// §2.3, lo esencial: desactivar + rotar `security_stamp` (corta todas
    /// las sesiones) + auditar con el motivo. El último admin activo no se
    /// desactiva (lo frena la base, QA-38), pero igual no entra.
    async fn dar_de_baja(&self, user_id: Uuid, motivo: &'static str) {
        self.recientes.lock().expect("mutex sano").remove(&user_id);
        let resultado = sqlx::query!(
            r#"update users set active = false, security_stamp = gen_random_uuid()
                where id = $1 and managed_by = 'directory_sync' and deleted_at is null"#,
            user_id
        )
        .execute(&self.pool)
        .await;
        if let Err(e) = resultado {
            tracing::warn!(%user_id, error = %e, "verificación de directorio: no se pudo desactivar (¿último admin?)");
            return;
        }
        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::UserDeactivated, None)
                .con_sujeto("user", user_id)
                .con_metadata(serde_json::json!({ "origen": "directory_check", "motivo": motivo })),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attrs(pares: &[(&str, &str)]) -> HashMap<String, Vec<String>> {
        pares.iter().map(|(k, v)| (k.to_string(), vec![v.to_string()])).collect()
    }

    #[test]
    fn ad_deshabilitada_expirada_y_vigente() {
        let ahora = OffsetDateTime::now_utc();
        assert_eq!(
            estado_de_entrada(&attrs(&[("userAccountControl", "514")]), ahora),
            EstadoEnDirectorio::Baja("directory_disabled")
        );
        assert_eq!(estado_de_entrada(&attrs(&[("userAccountControl", "512")]), ahora), EstadoEnDirectorio::Vigente);
        // 2001-01-01 en FILETIME: vencida.
        assert_eq!(
            estado_de_entrada(&attrs(&[("accountExpires", "126227808000000000")]), ahora),
            EstadoEnDirectorio::Baja("directory_expired")
        );
        assert_eq!(estado_de_entrada(&attrs(&[("accountExpires", "0")]), ahora), EstadoEnDirectorio::Vigente);
        assert_eq!(
            estado_de_entrada(&attrs(&[("accountExpires", "9223372036854775807")]), ahora),
            EstadoEnDirectorio::Vigente
        );
    }

    #[test]
    fn openldap_bloqueada_por_ppolicy() {
        let ahora = OffsetDateTime::now_utc();
        assert_eq!(
            estado_de_entrada(&attrs(&[("pwdAccountLockedTime", "000001010000Z")]), ahora),
            EstadoEnDirectorio::Baja("directory_disabled")
        );
        assert_eq!(estado_de_entrada(&HashMap::new(), ahora), EstadoEnDirectorio::Vigente);
    }
}
