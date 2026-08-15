// Autor: Athan Espinoza

use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct GrupoBloqueado {
    pub group_id: Uuid,
    pub name: String,
}

#[derive(Debug, Clone, Default)]
pub struct Bloqueos {
    pub groups: Vec<GrupoBloqueado>,
    pub resources: Vec<Uuid>,
}

impl Bloqueos {
    pub fn vacio(&self) -> bool {
        self.groups.is_empty() && self.resources.is_empty()
    }
}

#[derive(Debug, Clone, Default)]
pub struct Transferencia {
    pub owners: Vec<(Uuid, Uuid)>,
    pub managers: Vec<(Uuid, Uuid)>,
}

#[derive(Debug, Clone, Default)]
pub struct ResultadoPurgaUsuario {
    pub resources_huerfanos_eliminados: u64,
}

#[derive(Debug, Clone)]
pub struct ResumenUsuario {
    pub id: Uuid,
    pub email: String,
    pub display_name: String,
    pub active: bool,
    pub has_avatar: bool,
    pub groups: Vec<String>,
    /// Recursos que este usuario creó (`resources.created_by`), sin filtrar
    /// por `deleted_at` — mismo criterio que el resto de "cuántos tiene",
    /// no cuánto le queda vigente.
    pub owned_resources_count: i64,
    /// Grants directos (`permissions.grantee_type = 'user'`) sobre recursos
    /// que este usuario NO creó — no cuenta acceso heredado por grupo,
    /// simplificación documentada (igual criterio que otras cuentas
    /// aproximadas de este módulo, ej. `calcular_bloqueos`).
    pub shared_with_count: i64,
}
