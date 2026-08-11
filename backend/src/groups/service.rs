// Autor: Athan Espinoza

//! Service de grupos — nunca importa `axum`. La autoridad delegada de F-12
//! ("¿es este actor manager de este subárbol?") es una pregunta que depende
//! del `group_id` puntual, así que se resuelve acá, no en un extractor
//! genérico como `AdminUser` (ver `08-backend.md` sección 4).

use uuid::Uuid;

use crate::admin::repository::RoleRepository;
use crate::audit::models::{AuditEventType, EventoAuditoria};
use crate::error::DomainError;
use crate::eventos::{DomainEvent, EmisorDeEventos};
use crate::resources::repository::PermissionRepository;

use super::models::{EnvelopeParaMiembroNuevo, Group, Miembro};
use super::repository::{GroupMemberRepository, GroupRepository, OrganizationRepository};

pub struct GroupService<'a, G, M, O, P, R> {
    pub grupos: &'a G,
    pub miembros: &'a M,
    pub organizacion: &'a O,
    pub permisos: &'a P,
    pub roles: &'a R,
    pub eventos: EmisorDeEventos,
}

impl<'a, G, M, O, P, R> GroupService<'a, G, M, O, P, R>
where
    G: GroupRepository,
    M: GroupMemberRepository,
    O: OrganizationRepository,
    P: PermissionRepository,
    R: RoleRepository,
{
    async fn es_admin_org(&self, actor_id: Uuid) -> Result<bool, DomainError> {
        Ok(self.roles.usuario_tiene_permiso(actor_id, "*").await?)
    }

    /// F-22/módulo 1: "Administrador de Grupos" delegado — un rol custom con
    /// el permiso granular `groups.create` puede crear grupos raíz sin ser
    /// admin de organización. Sin tabla nueva: el catálogo de `role_permissions`
    /// ya es abierto, alcanza con asignarle este permiso a un rol vía
    /// `PUT /admin/roles/{id}` (matriz RBAC).
    async fn puede_crear_grupo_raiz(&self, actor_id: Uuid) -> Result<bool, DomainError> {
        if self.es_admin_org(actor_id).await? {
            return Ok(true);
        }
        Ok(self.roles.usuario_tiene_permiso(actor_id, "groups.create").await?)
    }

    /// Manager de `group_id` mismo, o de cualquiera de sus ancestros
    /// (alcance recursivo por default, F-12) — o admin de organización.
    async fn autorizado_para_administrar(&self, actor_id: Uuid, group_id: Uuid) -> Result<bool, DomainError> {
        if self.es_admin_org(actor_id).await? {
            return Ok(true);
        }
        let ancestros = self.grupos.ancestros_inclusive(group_id).await?;
        Ok(self.miembros.es_manager_de_alguno(actor_id, &ancestros).await?)
    }

    /// `GET /groups/{id}/resources` (F-12) — recursos actualmente
    /// compartidos con el grupo (`permissions.grantee_type = 'group'`) —
    /// lo que el cliente necesita para saber a cuáles re-sellar la DEK al
    /// agregar un miembro nuevo (`AgregarMiembroRequest.envelopes` exige
    /// cubrir exactamente este conjunto).
    pub async fn recursos_compartidos(&self, actor_id: Uuid, group_id: Uuid) -> Result<Vec<Uuid>, DomainError> {
        self.grupos.buscar(group_id).await?.ok_or(DomainError::NotFound)?;
        if !self.autorizado_para_administrar(actor_id, group_id).await? {
            return Err(DomainError::PermissionDenied);
        }
        Ok(self.permisos.recursos_por_grantee("group", group_id).await?)
    }

    /// `POST /groups` — sin `parent_group_id` exige admin de organización;
    /// con `parent_group_id` sólo exige ser manager de ese padre (o admin).
    pub async fn crear(
        &self,
        actor_id: Uuid,
        id: Uuid,
        name: &str,
        parent_group_id: Option<Uuid>,
    ) -> Result<Group, DomainError> {
        if name.trim().is_empty() {
            return Err(DomainError::ValidacionInvalida("name no puede estar vacío".into()));
        }

        let profundidad_nueva = match parent_group_id {
            None => {
                if !self.puede_crear_grupo_raiz(actor_id).await? {
                    return Err(DomainError::PermissionDenied);
                }
                1
            }
            Some(padre) => {
                if !self.autorizado_para_administrar(actor_id, padre).await? {
                    return Err(DomainError::PermissionDenied);
                }
                self.grupos.buscar(padre).await?.ok_or(DomainError::NotFound)?;
                self.grupos.profundidad(padre).await? + 1
            }
        };

        let max = self.organizacion.max_group_depth().await?;
        if profundidad_nueva > max {
            return Err(DomainError::ValidacionInvalida(format!(
                "excede la profundidad máxima de grupos ({max})"
            )));
        }

        self.grupos.crear(id, name, parent_group_id).await.map_err(|e| match e {
            crate::error::RepoError::Conflict => DomainError::Conflict,
            otro => DomainError::Interno(otro),
        })
    }

    /// `GET /groups` — raíces; el cliente arma el árbol completo recorriendo
    /// `GET /groups/{id}/subgroups` recursivamente, mismo criterio que F-09.
    pub async fn listar_raices(&self) -> Result<Vec<Group>, DomainError> {
        Ok(self.grupos.raices().await?)
    }

    pub async fn obtener(&self, group_id: Uuid) -> Result<Group, DomainError> {
        self.grupos.buscar(group_id).await?.ok_or(DomainError::NotFound)
    }

    pub async fn subgrupos(&self, group_id: Uuid) -> Result<Vec<Group>, DomainError> {
        Ok(self.grupos.hijos_directos(group_id).await?)
    }

    pub async fn miembros(&self, group_id: Uuid) -> Result<Vec<Miembro>, DomainError> {
        Ok(self.miembros.miembros_de(group_id).await?)
    }

    /// `PUT /groups/{id}/move` — rechaza ciclos y profundidad excedida.
    pub async fn mover(
        &self,
        actor_id: Uuid,
        group_id: Uuid,
        new_parent_group_id: Option<Uuid>,
    ) -> Result<(), DomainError> {
        self.grupos.buscar(group_id).await?.ok_or(DomainError::NotFound)?;

        if !self.autorizado_para_administrar(actor_id, group_id).await? {
            return Err(DomainError::PermissionDenied);
        }

        let profundidad_nueva = match new_parent_group_id {
            None => 1,
            Some(nuevo_padre) => {
                if nuevo_padre == group_id {
                    return Err(DomainError::CicloDeGrupo);
                }
                self.grupos.buscar(nuevo_padre).await?.ok_or(DomainError::NotFound)?;
                if !self.autorizado_para_administrar(actor_id, nuevo_padre).await? {
                    return Err(DomainError::PermissionDenied);
                }

                let ancestros_del_nuevo_padre = self.grupos.ancestros_inclusive(nuevo_padre).await?;
                if ancestros_del_nuevo_padre.contains(&group_id) {
                    return Err(DomainError::CicloDeGrupo);
                }

                self.grupos.profundidad(nuevo_padre).await? + 1
            }
        };

        let max = self.organizacion.max_group_depth().await?;
        if profundidad_nueva > max {
            return Err(DomainError::ValidacionInvalida(format!(
                "excede la profundidad máxima de grupos ({max})"
            )));
        }

        self.grupos.mover(group_id, new_parent_group_id).await?;
        Ok(())
    }

    /// F-12: agregar sella la DEK de cada recurso ya compartido con el
    /// grupo — si el grupo ya tiene acceso a N recursos, el caller tiene
    /// que traer exactamente N envelopes (ni de más ni de menos), o falla
    /// entero sin aplicar nada a medias.
    pub async fn agregar_miembro(
        &self,
        actor_id: Uuid,
        group_id: Uuid,
        user_id: Uuid,
        is_admin: bool,
        envelopes: Vec<EnvelopeParaMiembroNuevo>,
    ) -> Result<(), DomainError> {
        self.grupos.buscar(group_id).await?.ok_or(DomainError::NotFound)?;
        if !self.autorizado_para_administrar(actor_id, group_id).await? {
            return Err(DomainError::PermissionDenied);
        }

        let recursos_compartidos = self.permisos.recursos_por_grantee("group", group_id).await?;

        if !recursos_compartidos.is_empty() {
            let esperados: std::collections::HashSet<Uuid> = recursos_compartidos.into_iter().collect();
            let recibidos: std::collections::HashSet<Uuid> =
                envelopes.iter().map(|e| e.resource_id).collect();
            if esperados != recibidos {
                return Err(DomainError::ValidacionInvalida(
                    "los envelopes deben cubrir exactamente los recursos ya compartidos con el grupo".into(),
                ));
            }
        }

        let resultado = if envelopes.is_empty() {
            self.miembros.agregar_simple(group_id, user_id, is_admin).await
        } else {
            self.miembros.agregar_con_envelopes(group_id, user_id, is_admin, &envelopes).await
        };

        resultado.map_err(|e| match e {
            crate::error::RepoError::Conflict => DomainError::Conflict,
            otro => DomainError::Interno(otro),
        })?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::GroupMemberAdded, Some(actor_id))
                .con_sujeto("group", group_id)
                .con_metadata(serde_json::json!({ "user_id": user_id, "is_admin": is_admin })),
        ));

        Ok(())
    }

    pub async fn quitar_miembro(&self, actor_id: Uuid, group_id: Uuid, user_id: Uuid) -> Result<(), DomainError> {
        self.grupos.buscar(group_id).await?.ok_or(DomainError::NotFound)?;
        if !self.autorizado_para_administrar(actor_id, group_id).await? {
            return Err(DomainError::PermissionDenied);
        }

        let miembro = self.miembros.miembro(group_id, user_id).await?.ok_or(DomainError::NotFound)?;
        if miembro.is_admin {
            let managers = self.miembros.contar_managers(group_id).await?;
            let miembros_totales = self.miembros.contar_miembros(group_id).await?;
            // "No-vacío" tras la baja: si quitar a este miembro deja el
            // grupo con al menos otro integrante, el único manager no puede
            // desaparecer sin dejar a alguien más a cargo.
            if managers == 1 && miembros_totales > 1 {
                return Err(DomainError::UnicoManagerDeGrupo);
            }
        }

        let recursos_compartidos = self.permisos.recursos_por_grantee("group", group_id).await?;
        self.miembros.quitar(group_id, user_id, &recursos_compartidos).await?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::GroupMemberRemoved, Some(actor_id))
                .con_sujeto("group", group_id)
                .con_metadata(serde_json::json!({ "user_id": user_id })),
        ));

        Ok(())
    }

    /// `PUT /groups/{id}/members/{userId}` — promueve/degrada `is_admin`,
    /// nunca toca acceso a recursos.
    pub async fn set_manager(
        &self,
        actor_id: Uuid,
        group_id: Uuid,
        user_id: Uuid,
        is_admin: bool,
    ) -> Result<(), DomainError> {
        self.grupos.buscar(group_id).await?.ok_or(DomainError::NotFound)?;
        if !self.autorizado_para_administrar(actor_id, group_id).await? {
            return Err(DomainError::PermissionDenied);
        }

        let miembro = self.miembros.miembro(group_id, user_id).await?.ok_or(DomainError::NotFound)?;

        if miembro.is_admin && !is_admin {
            let managers = self.miembros.contar_managers(group_id).await?;
            if managers == 1 {
                return Err(DomainError::UnicoManagerDeGrupo);
            }
        }

        self.miembros.set_admin(group_id, user_id, is_admin).await?;

        let _ = self.eventos.send(DomainEvent::Auditoria(
            EventoAuditoria::nuevo(AuditEventType::GroupManagerChanged, Some(actor_id))
                .con_sujeto("group", group_id)
                .con_metadata(serde_json::json!({ "user_id": user_id, "is_admin": is_admin })),
        ));

        Ok(())
    }

    pub async fn eliminar(&self, actor_id: Uuid, group_id: Uuid) -> Result<(), DomainError> {
        self.grupos.buscar(group_id).await?.ok_or(DomainError::NotFound)?;
        if !self.autorizado_para_administrar(actor_id, group_id).await? {
            return Err(DomainError::PermissionDenied);
        }

        if self.grupos.tiene_hijos(group_id).await? {
            return Err(DomainError::GrupoTieneSubgrupos);
        }

        let subjects_owner = self.permisos.subjects_owner_de("group", group_id).await?;
        for (subject_type, subject_id) in subjects_owner {
            let hay_otro = self
                .permisos
                .existe_otro_owner(&subject_type, subject_id, "group", group_id)
                .await?;
            if !hay_otro {
                return Err(DomainError::GrupoEsUnicoOwner);
            }
        }

        self.grupos.eliminar(group_id).await?;
        Ok(())
    }
}
