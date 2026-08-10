// Autor: Athan Espinoza

//! Service de carpetas (F-09/F-11) — nunca importa `axum`. Reposicionar la
//! propia vista de una carpeta sigue sin control de acceso (F-09 original:
//! "nunca toca la vista de otro usuario", así que no hay nada ajeno que
//! proteger ahí). Lo que sí gana control de acceso (F-11, "permisos tipo
//! Passbolt") es: quién puede mover un recurso hacia/desde una carpeta ya
//! compartida, y quién puede compartir una carpeta — una carpeta sin
//! ninguna fila en `permissions` (nunca compartida, incluidas todas las
//! creadas antes de F-11) se trata como personal/sin restricción, mismo
//! bypass que hace Passbolt para carpetas 100% personales.

use uuid::Uuid;

use crate::error::DomainError;
use crate::resources::models::NivelPermiso;
use crate::resources::repository::PermissionRepository;

use super::models::{Folder, NodoDeArbol};
use super::repository::{FolderItemRepository, FolderRepository};

pub struct FolderService<'a, F, FI, P> {
    pub carpetas: &'a F,
    pub items: &'a FI,
    pub permisos: &'a P,
}

impl<'a, F, FI, P> FolderService<'a, F, FI, P>
where
    F: FolderRepository,
    FI: FolderItemRepository,
    P: PermissionRepository,
{
    pub async fn crear(
        &self,
        user_id: Uuid,
        id: Uuid,
        name_ciphertext: &[u8],
        name_nonce: &[u8],
        parent_folder_id: Option<Uuid>,
    ) -> Result<Folder, DomainError> {
        if let Some(padre) = parent_folder_id {
            self.carpetas
                .buscar(padre)
                .await?
                .ok_or_else(|| DomainError::ValidacionInvalida("parent_folder_id no existe".into()))?;
        }

        let carpeta = self.carpetas.crear(id).await?;
        self.items.insertar_carpeta(user_id, carpeta.id, parent_folder_id, name_ciphertext, name_nonce).await?;
        self.permisos.otorgar("folder", carpeta.id, user_id, NivelPermiso::Owner.as_db_str()).await?;
        Ok(carpeta)
    }

    pub async fn listar_arbol(&self, user_id: Uuid) -> Result<Vec<NodoDeArbol>, DomainError> {
        Ok(self.items.arbol_de(user_id).await?)
    }

    /// Reposiciona una carpeta sólo en el árbol de `user_id` — nunca toca la
    /// vista de otro usuario, aunque tenga la misma carpeta en la suya
    /// (F-09, criterio de aceptación literal). Sin chequeo de permisos: es
    /// 100% la vista propia de quien llama, no afecta a nadie más.
    pub async fn mover(
        &self,
        user_id: Uuid,
        folder_id: Uuid,
        new_parent_folder_id: Option<Uuid>,
    ) -> Result<(), DomainError> {
        if Some(folder_id) == new_parent_folder_id {
            return Err(DomainError::ValidacionInvalida("una carpeta no puede ser su propio padre".into()));
        }

        if !self.items.tiene_en_su_arbol(user_id, folder_id).await? {
            return Err(DomainError::NotFound);
        }

        if let Some(padre) = new_parent_folder_id {
            self.carpetas
                .buscar(padre)
                .await?
                .ok_or_else(|| DomainError::ValidacionInvalida("new_parent_folder_id no existe".into()))?;
        }

        self.items.reposicionar_carpeta(user_id, folder_id, new_parent_folder_id).await?;
        Ok(())
    }

    /// F-11: mueve un RECURSO a una carpeta (o a la raíz, `folder_id: None`)
    /// en el árbol de `user_id`. A diferencia de `mover` (reposicionar la
    /// vista propia de una carpeta, sin restricción), esto exige `update`
    /// sobre la carpeta destino si ya está compartida — moverlo a una
    /// carpeta compartida **nunca comparte el recurso automáticamente**
    /// (igual que Passbolt: compartir sigue siendo `compartir_recurso`,
    /// un paso client-side aparte, imposible de saltear en una arquitectura
    /// zero-knowledge — el servidor no puede otorgar acceso a un secreto
    /// cifrado).
    pub async fn mover_recurso(
        &self,
        user_id: Uuid,
        resource_id: Uuid,
        folder_id: Option<Uuid>,
    ) -> Result<(), DomainError> {
        if let Some(destino) = folder_id {
            self.carpetas
                .buscar(destino)
                .await?
                .ok_or_else(|| DomainError::ValidacionInvalida("folder_id no existe".into()))?;

            let compartida = self.permisos.existe_algun_permiso("folder", destino).await?;
            let autorizado = if compartida {
                self.permisos.tiene_permiso("folder", destino, user_id, NivelPermiso::Update.as_db_str()).await?
            } else {
                self.items.tiene_en_su_arbol(user_id, destino).await?
            };
            if !autorizado {
                return Err(DomainError::PermissionDenied);
            }
        }

        self.items.posicionar_recurso(user_id, resource_id, folder_id).await?;
        Ok(())
    }

    /// F-11: comparte una carpeta con otro usuario — exige `owner` sobre
    /// ella. El cliente ya reselló el nombre para el destinatario
    /// (`sellar_para`, mismo patrón que compartir un recurso); acá sólo se
    /// persiste el permiso nuevo y la fila de árbol del destinatario (nace
    /// en la raíz de su propio árbol — puede reposicionarla después con
    /// `mover`, sin que eso afecte a nadie más).
    pub async fn compartir(
        &self,
        actor_id: Uuid,
        folder_id: Uuid,
        grantee_user_id: Uuid,
        nivel: &str,
        name_ciphertext_para_destinatario: &[u8],
        name_nonce_para_destinatario: &[u8],
    ) -> Result<(), DomainError> {
        if !["read", "update", "owner"].contains(&nivel) {
            return Err(DomainError::ValidacionInvalida("nivel de permiso inválido".into()));
        }

        self.carpetas
            .buscar(folder_id)
            .await?
            .ok_or(DomainError::NotFound)?;

        if !self.permisos.tiene_permiso("folder", folder_id, actor_id, NivelPermiso::Owner.as_db_str()).await? {
            return Err(DomainError::PermissionDenied);
        }

        self.permisos.otorgar("folder", folder_id, grantee_user_id, nivel).await?;
        self.items
            .insertar_carpeta(grantee_user_id, folder_id, None, name_ciphertext_para_destinatario, name_nonce_para_destinatario)
            .await?;
        Ok(())
    }
}
