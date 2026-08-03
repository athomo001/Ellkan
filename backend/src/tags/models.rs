// Autor: Athan Espinoza

use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Tag {
    pub id: Uuid,
    pub name: String,
    pub is_shared: bool,
    pub created_by: Uuid,
}
