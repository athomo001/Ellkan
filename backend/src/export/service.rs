// Autor: Athan Espinoza

//! Service de F-27 (política + `/export-events`) y F-29 (export masivo) —
//! nunca importa `axum`. Ver `mod.rs` para el diseño de por qué
//! `reportar_evento` es, a la vez, el registro de auditoría y el único
//! gate server-side real de F-27.

use uuid::Uuid;

use crate::admin::repository::RoleRepository;
use crate::audit::models::{AuditEventType, EventoAuditoria};
use crate::error::DomainError;
use crate::eventos::{DomainEvent, EmisorDeEventos};

use super::models::{ExportPolicy, FilaExportGrupo, FilaExportUsuario, TipoEventoExport};
use super::repository::{ExportPolicyRepository, ExportRepository};

const FORMATOS_VALIDOS: [&str; 3] = ["kdbx", "csv", "cxf"];

pub struct ExportService<'a, P, E, R> {
    pub policy: &'a P,
    pub datos: &'a E,
    pub roles: &'a R,
    pub eventos: EmisorDeEventos,
}

impl<'a, P, E, R> ExportService<'a, P, E, R>
where
    P: ExportPolicyRepository,
    E: ExportRepository,
    R: RoleRepository,
{
    pub async fn politica(&self) -> Result<ExportPolicy, DomainError> {
        Ok(self.policy.obtener().await?)
    }

    pub async fn actualizar_politica(
        &self,
        actor_id: Uuid,
        nueva: ExportPolicy,
    ) -> Result<ExportPolicy, DomainError> {
        for formato in &nueva.allowed_formats {
            if !FORMATOS_VALIDOS.contains(&formato.as_str()) {
                return Err(DomainError::ValidacionInvalida(format!(
                    "formato desconocido: '{formato}' (válidos: kdbx, csv, cxf)"
                )));
            }
        }

        self.policy.actualizar(&nueva).await?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::ExportPolicyUpdated, Some(actor_id)).con_metadata(
                serde_json::json!({
                    "export_enabled": nueva.export_enabled,
                    "allowed_formats": nueva.allowed_formats,
                    "import_enabled": nueva.import_enabled,
                }),
            ),
        ));

        Ok(nueva)
    }

    /// Único gate server-side real de F-27 (ver comentario de `mod.rs`): el
    /// cliente llama esto **antes** de generar el archivo, y sólo arma el
    /// KDBX/CSV/CXF si la respuesta es `Ok`. Nada se audita si el intento
    /// se rechaza acá — no pasó ninguna exportación real.
    pub async fn reportar_evento(
        &self,
        actor_id: Uuid,
        tipo: TipoEventoExport,
        format: &str,
        resource_count: i32,
    ) -> Result<(), DomainError> {
        if !FORMATOS_VALIDOS.contains(&format) {
            return Err(DomainError::ValidacionInvalida(format!(
                "formato desconocido: '{format}' (válidos: kdbx, csv, cxf)"
            )));
        }

        let politica = self.policy.obtener().await?;
        if !politica.allowed_formats.iter().any(|f| f == format) {
            return Err(DomainError::ValidacionInvalida(format!(
                "el formato '{format}' no está habilitado por política"
            )));
        }

        // F-27: la excepción de admin/owner (Ellkan no tiene un rol "Owner"
        // de organización separado del rol admin — a diferencia de
        // Bitwarden, de donde viene esta terminología, acá "admin/owner" se
        // traduce directo al permiso comodín `"*"` ya usado por
        // `AdminUser`) sólo aplica a `export_enabled`, nunca a
        // `allowed_formats` ni a `import_enabled` — ningún camino de acá
        // abajo la deja saltear ninguna de esas dos.
        let via_excepcion_admin = match tipo {
            TipoEventoExport::Export if !politica.export_enabled => {
                if !self.roles.usuario_tiene_permiso(actor_id, "*").await? {
                    return Err(DomainError::PermissionDenied);
                }
                true
            }
            TipoEventoExport::Export => false,
            TipoEventoExport::Import if !politica.import_enabled => {
                return Err(DomainError::PermissionDenied);
            }
            TipoEventoExport::Import => false,
        };

        let (evento, tipo_str) = match tipo {
            TipoEventoExport::Export => (AuditEventType::ExportPerformed, "export"),
            TipoEventoExport::Import => (AuditEventType::ImportPerformed, "import"),
        };

        let _ = self.eventos.send(DomainEvent::Auditoria(EventoAuditoria::nuevo(evento, Some(actor_id)).con_metadata(
            serde_json::json!({
                "event_type": tipo_str,
                "format": format,
                "resource_count": resource_count,
                "via_role_exception": via_excepcion_admin,
            }),
        )));

        Ok(())
    }

    pub async fn listar_usuarios(&self, actor_id: Uuid) -> Result<Vec<FilaExportUsuario>, DomainError> {
        let filas = self.datos.listar_usuarios().await?;
        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::UsersExported, Some(actor_id))
                .con_metadata(serde_json::json!({ "count": filas.len() })),
        ));
        Ok(filas)
    }

    pub async fn listar_grupos(&self, actor_id: Uuid) -> Result<Vec<FilaExportGrupo>, DomainError> {
        let filas = self.datos.listar_grupos().await?;
        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::GroupsExported, Some(actor_id))
                .con_metadata(serde_json::json!({ "count": filas.len() })),
        ));
        Ok(filas)
    }
}
