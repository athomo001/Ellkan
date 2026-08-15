// Autor: Athan Espinoza

use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Group {
    pub id: Uuid,
    pub name: String,
    pub parent_group_id: Option<Uuid>,
    /// 2026-08-13: excepción a la visibilidad de compartir acotada por
    /// grupo (0037) — los miembros de un grupo `share_exempt` ven y pueden
    /// compartir con cualquier usuario de la org, sin ganar ningún otro
    /// privilegio de admin. Sólo lo puede tocar un admin de organización.
    pub share_exempt: bool,
}

/// `GET /me/groups` — hallazgo real de uso 2026-08-11: no había forma de
/// que un usuario viera en su propio perfil a qué grupos pertenece ni si es
/// admin de alguno.
#[derive(Debug, Clone)]
pub struct GrupoDeUsuario {
    pub group_id: Uuid,
    pub name: String,
    pub is_admin: bool,
}

#[derive(Debug, Clone)]
pub struct Miembro {
    pub user_id: Uuid,
    pub is_admin: bool,
    /// Hallazgo real de uso 2026-08-11: `/admin/groups` mostraba el `user_id`
    /// crudo en la lista de miembros — nadie reconoce un UUID a simple vista.
    pub email: String,
    pub display_name: String,
}

/// Un envelope de secreto ya sellado por el caller para un recurso que el
/// grupo ya tiene compartido — ver `GroupService::agregar_miembro`.
#[derive(Debug, Clone)]
pub struct EnvelopeParaMiembroNuevo {
    pub resource_id: Uuid,
    pub sealed_dek: Vec<u8>,
    pub secret_ciphertext: Vec<u8>,
    pub secret_nonce: Vec<u8>,
}
