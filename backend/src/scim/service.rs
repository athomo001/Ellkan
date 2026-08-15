// Autor: Athan Espinoza

//! Service de SCIM 2.0 (F-18) — nunca importa `axum`.

use uuid::Uuid;

use crate::audit::models::{AuditEventType, EventoAuditoria};
use crate::error::DomainError;
use crate::eventos::{DomainEvent, EmisorDeEventos};

use super::models::{ResultadoCrearUsuario, ScimUser};
use super::repository::ScimUserRepository;

pub struct ScimService<'a, U> {
    pub usuarios: &'a U,
    pub eventos: EmisorDeEventos,
}

impl<'a, U> ScimService<'a, U>
where
    U: ScimUserRepository,
{
    /// RFC 7644 §3.3: idempotente por `externalId` — reintentar el mismo
    /// alta nunca crea un duplicado. Conflicto de email con una cuenta
    /// gestionada por otro `externalId` (o creada manualmente) falla
    /// explícito, nunca fusiona ni pisa silenciosamente.
    pub async fn crear_usuario(
        &self,
        external_id: &str,
        email: &str,
        display_name: &str,
    ) -> Result<ResultadoCrearUsuario, DomainError> {
        if let Some(existente) = self.usuarios.buscar_por_external_id(external_id).await? {
            return Ok(ResultadoCrearUsuario::YaExistiaPorExternalId(existente));
        }

        if self.usuarios.buscar_por_email(email).await?.is_some() {
            return Ok(ResultadoCrearUsuario::ConflictoDeEmail);
        }

        let creado = self.usuarios.crear(external_id, email, display_name).await?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::ScimUserCreated, None)
                .con_sujeto("user", creado.id)
                .con_metadata(serde_json::json!({ "external_id": external_id })),
        ));

        Ok(ResultadoCrearUsuario::Creado(creado))
    }

    pub async fn obtener(&self, id: Uuid) -> Result<ScimUser, DomainError> {
        self.usuarios.buscar_por_id(id).await?.ok_or(DomainError::NotFound)
    }

    pub async fn listar(&self, start_index: i64, count: i64) -> Result<(Vec<ScimUser>, i64), DomainError> {
        Ok(self.usuarios.listar(start_index.max(1) - 1, count.clamp(1, 200)).await?)
    }

    /// `PATCH /scim/v2/Users/{id}` — sólo soporta el caso real que F-18
    /// pide: activar/desactivar. Desactivar invalida sesiones activas de
    /// inmediato (mismo mecanismo que F-40/F-20, rotar `security_stamp`),
    /// nunca borra secretos ni claves — sólo revoca acceso.
    pub async fn actualizar_activo(&self, id: Uuid, active: bool) -> Result<ScimUser, DomainError> {
        if !self.usuarios.actualizar_activo(id, active).await? {
            return Err(DomainError::NotFound);
        }

        let evento = if active { AuditEventType::ScimUserUpdated } else { AuditEventType::ScimUserDeactivated };
        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(evento, None).con_sujeto("user", id),
        ));

        self.obtener(id).await
    }
}
