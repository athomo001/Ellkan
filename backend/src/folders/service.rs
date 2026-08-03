// Autor: Athan Espinoza

//! Service de carpetas — nunca importa `axum`. Sin chequeo de permisos: F-09
//! es deliberadamente una capa organizativa sin control de acceso propio.

use uuid::Uuid;

use crate::error::DomainError;

use super::models::{Folder, NodoDeArbol};
use super::repository::{FolderItemRepository, FolderRepository};

pub struct FolderService<'a, F, FI> {
    pub carpetas: &'a F,
    pub items: &'a FI,
}

impl<'a, F, FI> FolderService<'a, F, FI>
where
    F: FolderRepository,
    FI: FolderItemRepository,
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

        let carpeta = self.carpetas.crear(id, name_ciphertext, name_nonce).await?;
        self.items.posicionar(user_id, carpeta.id, parent_folder_id).await?;
        Ok(carpeta)
    }

    pub async fn listar_arbol(&self, user_id: Uuid) -> Result<Vec<NodoDeArbol>, DomainError> {
        Ok(self.items.arbol_de(user_id).await?)
    }

    /// Reposiciona una carpeta sólo en el árbol de `user_id` — nunca toca la
    /// vista de otro usuario, aunque tenga la misma carpeta en la suya
    /// (F-09, criterio de aceptación literal).
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

        self.items.posicionar(user_id, folder_id, new_parent_folder_id).await?;
        Ok(())
    }
}
