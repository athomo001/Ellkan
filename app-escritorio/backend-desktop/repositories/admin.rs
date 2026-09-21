// Autor: Athan Espinoza

//! Segunda implementación (SQLite, modo escritorio) de `RoleRepository` —
//! sin tabla: el módulo de roles se compila afuera en este modo (spec/13
//! §16, "el rol es vestigial"). `usuario_tiene_permiso` siempre `true`
//! (cambiado de `false` el 2026-09-16, ver spec/10-mapa-mental.md "Fase
//! 3.1 en curso"): el único usuario local es, por definición, dueño de
//! TODO lo que existe en su bóveda — no hay nadie más de quien
//! protegerlo. Antes de este cambio, `FolderService::es_privilegiado`
//! (`grupos.es_admin_de_algun_grupo() || roles.usuario_tiene_permiso(_,
//! "*")`, ambos siempre `false` en este modo) nunca daba `true`, así que
//! **crear o mover una carpeta a otra carpeta (anidar) era imposible** —
//! `FolderService::crear`/`mover` devolvían `PermissionDenied` en cuanto
//! `parent_folder_id`/`new_parent_folder_id` no era `None`, dejando sólo
//! carpetas planas en la raíz. Verificado seguro: los otros dos call
//! sites de este método (`ResourceService::eliminar`/`puede_borrar`,
//! "¿es admin de organización?" antes del chequeo real de `owner`) sólo
//! ganan un atajo — con 1 usuario, "admin de organización" y "dueño del
//! recurso" son la misma persona, `true` no abre ningún acceso que el
//! chequeo de `owner` no diera ya.

use uuid::Uuid;

use crate::error::RepoError;

use crate::admin::models::Role;
use crate::admin::repository::RoleRepository;

#[derive(Clone, Default)]
pub struct SqliteRoleRepository;

impl RoleRepository for SqliteRoleRepository {
    async fn listar(&self) -> Result<Vec<Role>, RepoError> {
        Ok(Vec::new())
    }

    async fn buscar(&self, _id: Uuid) -> Result<Option<Role>, RepoError> {
        Ok(None)
    }

    async fn id_por_nombre(&self, _name: &str) -> Result<Option<Uuid>, RepoError> {
        Ok(None)
    }

    async fn crear(&self, _name: &str, _permisos: &[String]) -> Result<Role, RepoError> {
        unimplemented!("modo escritorio: sin roles, no hay UI que llegue acá")
    }

    async fn reemplazar_permisos(&self, _role_id: Uuid, _permisos: &[String]) -> Result<Option<Role>, RepoError> {
        unimplemented!("modo escritorio: sin roles, no hay UI que llegue acá")
    }

    async fn usuario_tiene_permiso(&self, _user_id: Uuid, _permission: &str) -> Result<bool, RepoError> {
        Ok(true)
    }

    async fn permisos_de_usuario(&self, _user_id: Uuid) -> Result<Vec<String>, RepoError> {
        Ok(Vec::new())
    }

    async fn listar_emails_con_permiso(&self, _permission: &str) -> Result<Vec<String>, RepoError> {
        Ok(Vec::new())
    }
}
