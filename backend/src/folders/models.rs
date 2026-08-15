// Autor: Athan Espinoza

use uuid::Uuid;

/// F-11: `folders` sólo guarda el `id` compartido — el nombre (cifrado) es
/// por-usuario y vive en `folder_items` (una fila por destinatario, cada
/// uno con su propio sellado), no acá.
#[derive(Debug, Clone)]
pub struct Folder {
    pub id: Uuid,
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
