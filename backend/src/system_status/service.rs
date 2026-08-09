// Autor: Athan Espinoza

//! Service de "Estado del sistema" (F-43) — nunca importa `axum`. Cada check
//! se resuelve independiente: si el repo correspondiente falla, ese check
//! queda en `NivelCheck::Error` con sus campos numéricos en cero, nunca se
//! propaga como error del endpoint completo (`handlers.rs`) ni filtra el
//! detalle interno del error (`sqlx::Error`) al cliente — sólo el nivel.

use super::models::{Check, GrupoChecks, NivelCheck};
use super::repository::SystemStatusRepository;
use crate::directory_sync::repository::DirectorySyncConfigRepository;
use crate::metadata::repository::MetadataKeyRepository;
use crate::notificaciones::OutboundEmailRepository;
use crate::smtp_config::repository::SmtpConfigRepository;
use crate::sso::repository::SsoConfigRepository;

/// Backlog de correo saliente por encima de esto ya es una advertencia, no
/// todavía un error — el poller de `notificaciones.rs` corre cada pocos
/// segundos, un pico transitorio es normal.
const UMBRAL_PENDIENTES_ADVERTENCIA: i64 = 50;

pub struct SystemStatusService<'a, S, E, SM, SS, DS, MK> {
    pub system_status: &'a S,
    pub emails: &'a E,
    pub smtp_config: &'a SM,
    pub sso_config: &'a SS,
    pub directory_sync_config: &'a DS,
    pub claves_metadata: &'a MK,
}

impl<'a, S, E, SM, SS, DS, MK> SystemStatusService<'a, S, E, SM, SS, DS, MK>
where
    S: SystemStatusRepository,
    E: OutboundEmailRepository,
    SM: SmtpConfigRepository,
    SS: SsoConfigRepository,
    DS: DirectorySyncConfigRepository,
    MK: MetadataKeyRepository,
{
    pub async fn obtener_todo(&self) -> Vec<GrupoChecks> {
        vec![
            GrupoChecks { categoria: "entorno", checks: vec![self.version_app()] },
            GrupoChecks { categoria: "base_datos", checks: vec![self.db_ping().await, self.db_migraciones().await] },
            GrupoChecks {
                categoria: "correo",
                checks: vec![self.smtp_configurado().await, self.correo_backlog().await],
            },
            GrupoChecks {
                categoria: "integraciones",
                checks: vec![self.sso_configurado().await, self.directory_sync_configurado().await],
            },
            GrupoChecks { categoria: "seguridad", checks: vec![self.metadata_key_rotacion().await] },
        ]
    }

    fn version_app(&self) -> Check {
        Check::VersionApp { nivel: NivelCheck::Ok, version: env!("CARGO_PKG_VERSION").to_string() }
    }

    async fn db_ping(&self) -> Check {
        match self.system_status.ping().await {
            Ok(()) => Check::DbPing { nivel: NivelCheck::Ok },
            Err(e) => {
                tracing::error!(error = %e, "system-status: falló el ping a la base de datos");
                Check::DbPing { nivel: NivelCheck::Error }
            }
        }
    }

    async fn db_migraciones(&self) -> Check {
        match self.system_status.migraciones().await {
            Ok((total, fallidas)) => Check::DbMigraciones {
                nivel: if fallidas > 0 { NivelCheck::Error } else { NivelCheck::Ok },
                aplicadas: total,
                fallidas,
            },
            Err(e) => {
                tracing::error!(error = %e, "system-status: falló la lectura de migraciones aplicadas");
                Check::DbMigraciones { nivel: NivelCheck::Error, aplicadas: 0, fallidas: 0 }
            }
        }
    }

    async fn smtp_configurado(&self) -> Check {
        match self.smtp_config.obtener().await {
            Ok(cfg) => {
                let configurado = cfg.esta_configurado();
                Check::SmtpConfigurado {
                    nivel: if configurado { NivelCheck::Ok } else { NivelCheck::Advertencia },
                    configurado,
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "system-status: falló la lectura de smtp_config");
                Check::SmtpConfigurado { nivel: NivelCheck::Error, configurado: false }
            }
        }
    }

    async fn correo_backlog(&self) -> Check {
        match self.emails.contar_por_estado().await {
            Ok((pendientes, fallidos)) => {
                let nivel = if fallidos > 0 {
                    NivelCheck::Error
                } else if pendientes > UMBRAL_PENDIENTES_ADVERTENCIA {
                    NivelCheck::Advertencia
                } else {
                    NivelCheck::Ok
                };
                Check::CorreoBacklog { nivel, pendientes, fallidos }
            }
            Err(e) => {
                tracing::error!(error = %e, "system-status: falló el conteo de la cola de correo saliente");
                Check::CorreoBacklog { nivel: NivelCheck::Error, pendientes: 0, fallidos: 0 }
            }
        }
    }

    async fn sso_configurado(&self) -> Check {
        match self.sso_config.obtener().await {
            Ok(cfg) => {
                let configurado = cfg.issuer_url.is_some() && cfg.client_id.is_some();
                Check::SsoConfigurado { nivel: NivelCheck::Ok, configurado }
            }
            Err(e) => {
                tracing::error!(error = %e, "system-status: falló la lectura de sso_config");
                Check::SsoConfigurado { nivel: NivelCheck::Error, configurado: false }
            }
        }
    }

    async fn directory_sync_configurado(&self) -> Check {
        match self.directory_sync_config.obtener().await {
            Ok(cfg) => {
                let configurado = cfg.ldap_url.is_some();
                let nivel = if configurado && cfg.last_sync_at.is_none() { NivelCheck::Advertencia } else { NivelCheck::Ok };
                Check::DirectorySyncConfigurado { nivel, configurado, ultima_sincronizacion: cfg.last_sync_at }
            }
            Err(e) => {
                tracing::error!(error = %e, "system-status: falló la lectura de directory_sync_config");
                Check::DirectorySyncConfigurado {
                    nivel: NivelCheck::Error,
                    configurado: false,
                    ultima_sincronizacion: None,
                }
            }
        }
    }

    async fn metadata_key_rotacion(&self) -> Check {
        match self.claves_metadata.contar_activas().await {
            Ok(claves_activas) => Check::MetadataKeyRotacion {
                nivel: if claves_activas > 1 { NivelCheck::Advertencia } else { NivelCheck::Ok },
                claves_activas,
            },
            Err(e) => {
                tracing::error!(error = %e, "system-status: falló el conteo de claves de metadata activas");
                Check::MetadataKeyRotacion { nivel: NivelCheck::Error, claves_activas: 0 }
            }
        }
    }
}
