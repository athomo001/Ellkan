// Autor: Athan Espinoza

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::models::{Bloqueos, ResumenUsuario, Transferencia};

#[derive(Debug, Serialize)]
pub struct UsuarioResponse {
    pub id: Uuid,
    pub email: String,
    pub display_name: String,
    pub active: bool,
}

impl From<ResumenUsuario> for UsuarioResponse {
    fn from(r: ResumenUsuario) -> Self {
        Self { id: r.id, email: r.email, display_name: r.display_name, active: r.active }
    }
}

#[derive(Debug, Serialize)]
pub struct DryRunResponse {
    pub blocked_groups: Vec<GrupoBloqueadoResponse>,
    pub blocked_resources: Vec<Uuid>,
    pub blocks_purge: bool,
}

#[derive(Debug, Serialize)]
pub struct GrupoBloqueadoResponse {
    pub group_id: Uuid,
    pub name: String,
}

impl From<Bloqueos> for DryRunResponse {
    fn from(b: Bloqueos) -> Self {
        Self {
            blocks_purge: !b.vacio(),
            blocked_groups: b.groups.into_iter().map(|g| GrupoBloqueadoResponse { group_id: g.group_id, name: g.name }).collect(),
            blocked_resources: b.resources,
        }
    }
}

#[derive(Debug, Deserialize, Default)]
pub struct PurgarRequest {
    #[serde(default)]
    pub transfer: TransferDto,
}

#[derive(Debug, Deserialize, Default)]
pub struct TransferDto {
    #[serde(default)]
    pub owners: Vec<OwnerTransferDto>,
    #[serde(default)]
    pub managers: Vec<ManagerTransferDto>,
}

#[derive(Debug, Deserialize)]
pub struct OwnerTransferDto {
    pub resource_id: Uuid,
    pub new_owner_user_id: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct ManagerTransferDto {
    pub group_id: Uuid,
    pub new_manager_user_id: Uuid,
}

impl From<TransferDto> for Transferencia {
    fn from(t: TransferDto) -> Self {
        Self {
            owners: t.owners.into_iter().map(|o| (o.resource_id, o.new_owner_user_id)).collect(),
            managers: t.managers.into_iter().map(|m| (m.group_id, m.new_manager_user_id)).collect(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct PurgaResponse {
    pub resources_huerfanos_eliminados: u64,
}

#[derive(Debug, Deserialize)]
pub struct ActualizarActivoRequest {
    pub active: bool,
}
