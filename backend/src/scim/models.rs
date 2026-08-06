// Autor: Athan Espinoza

use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ScimUser {
    pub id: Uuid,
    pub external_id: Option<String>,
    pub email: String,
    pub display_name: String,
    pub active: bool,
}

#[derive(Debug, Clone)]
pub enum ResultadoCrearUsuario {
    Creado(ScimUser),
    /// RFC 7644: reintentar el mismo `externalId` no crea un duplicado —
    /// devuelve el recurso ya existente con `409`, no lo pisa.
    YaExistiaPorExternalId(ScimUser),
    /// El email ya pertenece a una cuenta que no es este mismo recurso SCIM
    /// (creada a mano, por self-registration, o por otro `externalId`).
    ConflictoDeEmail,
}
