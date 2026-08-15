// Autor: Athan Espinoza

//! Service de tags — nunca importa `axum`. Reusa `PermissionRepository` de
//! `resources` (mismo trait ya usado para `read`/`update`/`owner` sobre
//! recursos) en vez de duplicar el concepto de nivel de acceso.

use uuid::Uuid;

use crate::error::DomainError;
use crate::resources::models::NivelPermiso;
use crate::resources::repository::PermissionRepository;

use super::models::Tag;
use super::repository::TagRepository;

pub struct TagService<'a, T, P> {
    pub tags: &'a T,
    pub permisos: &'a P,
}

impl<'a, T, P> TagService<'a, T, P>
where
    T: TagRepository,
    P: PermissionRepository,
{
    /// `POST /tags` — crear `is_shared: true` exige admin (chequeado por el
    /// caller vía `AdminUser` cuando corresponde; acá se re-verifica porque
    /// el Service es la fuente de verdad de la regla de negocio, no confía
    /// en que el Controller siempre la aplique bien).
    pub async fn crear(
        &self,
        actor_id: Uuid,
        es_admin: bool,
        id: Uuid,
        name: &str,
        is_shared: bool,
    ) -> Result<Tag, DomainError> {
        if name.trim().is_empty() {
            return Err(DomainError::ValidacionInvalida("name no puede estar vacío".into()));
        }
        if is_shared && !es_admin {
            return Err(DomainError::PermissionDenied);
        }
        Ok(self.tags.crear(id, name, is_shared, actor_id).await?)
    }

    pub async fn listar_disponibles(&self, actor_id: Uuid) -> Result<Vec<Tag>, DomainError> {
        Ok(self.tags.listar_disponibles_para(actor_id).await?)
    }

    async fn autorizar_aplicar_o_quitar(&self, actor_id: Uuid, resource_id: Uuid, tag_id: Uuid) -> Result<(), DomainError> {
        let tag = self.tags.buscar(tag_id).await?.ok_or(DomainError::NotFound)?;

        // Un tag personal ajeno ni siquiera puede aplicarse — no es un
        // objeto que el actor tenga autoridad sobre.
        if !tag.is_shared && tag.created_by != Some(actor_id) {
            return Err(DomainError::PermissionDenied);
        }

        if !self
            .permisos
            .tiene_permiso("resource", resource_id, actor_id, NivelPermiso::Update.as_db_str())
            .await?
        {
            return Err(DomainError::PermissionDenied);
        }

        Ok(())
    }

    pub async fn aplicar(&self, actor_id: Uuid, resource_id: Uuid, tag_id: Uuid) -> Result<(), DomainError> {
        self.autorizar_aplicar_o_quitar(actor_id, resource_id, tag_id).await?;
        self.tags.aplicar(resource_id, tag_id).await?;
        Ok(())
    }

    pub async fn quitar(&self, actor_id: Uuid, resource_id: Uuid, tag_id: Uuid) -> Result<(), DomainError> {
        self.autorizar_aplicar_o_quitar(actor_id, resource_id, tag_id).await?;
        self.tags.quitar(resource_id, tag_id).await?;
        Ok(())
    }

    /// `GET /resources?tag_id=...` (extensión de `03-api-contrato.md`, "GET
    /// /resources ... filtros por carpeta/tag"). Un tag personal ajeno
    /// devuelve `NotFound`, no una lista vacía — no revela ni siquiera que
    /// el tag existe (mismo criterio de "un tag personal de A nunca aparece
    /// para B").
    pub async fn recursos_por_tag(&self, actor_id: Uuid, tag_id: Uuid) -> Result<Vec<Uuid>, DomainError> {
        let tag = self.tags.buscar(tag_id).await?.ok_or(DomainError::NotFound)?;
        if !tag.is_shared && tag.created_by != Some(actor_id) {
            return Err(DomainError::NotFound);
        }
        Ok(self.tags.recursos_visibles_con_tag(actor_id, tag_id).await?)
    }
}
