// Autor: Athan Espinoza

//! Segunda implementación (SQLite, modo escritorio) de `GroupMemberRepository`
//! — sin tabla: el módulo `groups` completo se compila afuera en este modo
//! (spec/13 §3, "el rol es vestigial"/sin admin/sin equipo), pero
//! `resources::service::ResourceService` sigue genérico sobre este trait
//! (el caso "¿el recurso vive en una carpeta de un grupo?" nunca aplica con
//! 1 solo usuario, sin grupos). Todo colapsa a "no hay grupos": vacío/falso.

use uuid::Uuid;

use crate::error::RepoError;

use crate::groups::models::{EnvelopeParaMiembroNuevo, GrupoDeUsuario, Miembro};
use crate::groups::repository::GroupMemberRepository;

#[derive(Clone, Default)]
pub struct SqliteGroupMemberRepository;

impl GroupMemberRepository for SqliteGroupMemberRepository {
    async fn agregar_simple(&self, _group_id: Uuid, _user_id: Uuid, _is_admin: bool) -> Result<(), RepoError> {
        unimplemented!("modo escritorio: sin grupos, no hay UI que llegue acá")
    }

    async fn agregar_con_envelopes(
        &self,
        _group_id: Uuid,
        _user_id: Uuid,
        _is_admin: bool,
        _envelopes: &[EnvelopeParaMiembroNuevo],
    ) -> Result<(), RepoError> {
        unimplemented!("modo escritorio: sin grupos, no hay UI que llegue acá")
    }

    async fn quitar(&self, _group_id: Uuid, _user_id: Uuid, _resource_ids_a_revocar: &[Uuid]) -> Result<bool, RepoError> {
        unimplemented!("modo escritorio: sin grupos, no hay UI que llegue acá")
    }

    async fn es_miembro(&self, _group_id: Uuid, _user_id: Uuid) -> Result<bool, RepoError> {
        Ok(false)
    }

    async fn miembro(&self, _group_id: Uuid, _user_id: Uuid) -> Result<Option<Miembro>, RepoError> {
        Ok(None)
    }

    async fn es_manager_de_alguno(&self, _user_id: Uuid, _group_ids: &[Uuid]) -> Result<bool, RepoError> {
        Ok(false)
    }

    async fn set_admin(&self, _group_id: Uuid, _user_id: Uuid, _is_admin: bool) -> Result<bool, RepoError> {
        unimplemented!("modo escritorio: sin grupos, no hay UI que llegue acá")
    }

    async fn miembros_de(&self, _group_id: Uuid) -> Result<Vec<Miembro>, RepoError> {
        Ok(Vec::new())
    }

    async fn grupos_de(&self, _user_id: Uuid) -> Result<Vec<GrupoDeUsuario>, RepoError> {
        Ok(Vec::new())
    }

    async fn es_admin_de_algun_grupo(&self, _user_id: Uuid) -> Result<bool, RepoError> {
        Ok(false)
    }

    async fn grupos_administrados_por(&self, _user_id: Uuid) -> Result<Vec<Uuid>, RepoError> {
        Ok(Vec::new())
    }

    async fn grupos_gestionados_de(&self, _user_id: Uuid) -> Result<Vec<GrupoDeUsuario>, RepoError> {
        Ok(Vec::new())
    }
}
