// Autor: Athan Espinoza

use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Folder {
    pub id: Uuid,
    pub name_ciphertext: Vec<u8>,
    pub name_nonce: Vec<u8>,
}

/// Una fila de `folder_items` ya resuelta contra `folders` — la vista de
/// árbol de un usuario es una lista plana de estos nodos, el cliente arma el
/// árbol siguiendo `parent_folder_id`.
#[derive(Debug, Clone)]
pub struct NodoDeArbol {
    pub folder_id: Uuid,
    pub parent_folder_id: Option<Uuid>,
    pub name_ciphertext: Vec<u8>,
    pub name_nonce: Vec<u8>,
}
