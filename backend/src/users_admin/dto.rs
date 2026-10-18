// Autor: Athan Espinoza

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::DomainError;

use super::models::{Bloqueos, DestinoPropiedad, PersonaConAcceso, RecursoBloqueado, ResumenUsuario, Transferencia};

#[derive(Debug, Serialize)]
pub struct UsuarioResponse {
    pub id: Uuid,
    pub email: String,
    pub display_name: String,
    pub active: bool,
    pub has_avatar: bool,
    pub groups: Vec<String>,
    pub owned_resources_count: i64,
    pub shared_with_count: i64,
}

impl From<ResumenUsuario> for UsuarioResponse {
    fn from(r: ResumenUsuario) -> Self {
        Self {
            id: r.id,
            email: r.email,
            display_name: r.display_name,
            active: r.active,
            has_avatar: r.has_avatar,
            groups: r.groups,
            owned_resources_count: r.owned_resources_count,
            shared_with_count: r.shared_with_count,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct DryRunResponse {
    pub blocked_groups: Vec<GrupoBloqueadoResponse>,
    /// Sólo los ids, como antes — se mantiene para no romper clientes viejos.
    pub blocked_resources: Vec<Uuid>,
    /// Lo mismo con el detalle para armar la transferencia: con quién está
    /// compartido cada recurso, quién puede recibirlo y qué se sugiere.
    pub blocked_resources_detail: Vec<RecursoBloqueadoResponse>,
    pub blocks_purge: bool,
}

#[derive(Debug, Serialize)]
pub struct GrupoBloqueadoResponse {
    pub group_id: Uuid,
    pub name: String,
    pub suggested_manager: Option<PersonaResponse>,
}

#[derive(Debug, Serialize)]
pub struct PersonaResponse {
    pub user_id: Uuid,
    pub email: String,
    pub display_name: String,
}

impl From<PersonaConAcceso> for PersonaResponse {
    fn from(p: PersonaConAcceso) -> Self {
        Self { user_id: p.user_id, email: p.email, display_name: p.display_name }
    }
}

#[derive(Debug, Serialize)]
pub struct GrupoConAccesoResponse {
    pub group_id: Uuid,
    pub name: String,
    pub level: String,
    pub admins: Vec<PersonaResponse>,
    pub members_with_access: i64,
}

#[derive(Debug, Serialize)]
pub struct UsuarioConAccesoResponse {
    #[serde(flatten)]
    pub persona: PersonaResponse,
    pub level: String,
}

#[derive(Debug, Serialize)]
pub struct RecursoBloqueadoResponse {
    pub resource_id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: time::OffsetDateTime,
    pub groups: Vec<GrupoConAccesoResponse>,
    pub users: Vec<UsuarioConAccesoResponse>,
    /// `null` = nadie activo puede recibir la propiedad.
    pub suggestion: Option<DestinoDto>,
}

impl From<RecursoBloqueado> for RecursoBloqueadoResponse {
    fn from(r: RecursoBloqueado) -> Self {
        Self {
            resource_id: r.resource_id,
            created_at: r.created_at,
            groups: r
                .grupos
                .into_iter()
                .map(|g| GrupoConAccesoResponse {
                    group_id: g.group_id,
                    name: g.name,
                    level: g.level,
                    admins: g.admins.into_iter().map(PersonaResponse::from).collect(),
                    members_with_access: g.miembros_con_acceso,
                })
                .collect(),
            users: r
                .usuarios
                .into_iter()
                .map(|u| UsuarioConAccesoResponse { persona: u.persona.into(), level: u.level })
                .collect(),
            suggestion: r.sugerencia.map(DestinoDto::from),
        }
    }
}

impl From<Bloqueos> for DryRunResponse {
    fn from(b: Bloqueos) -> Self {
        Self {
            blocks_purge: !b.vacio(),
            blocked_groups: b
                .groups
                .into_iter()
                .map(|g| GrupoBloqueadoResponse {
                    group_id: g.group_id,
                    name: g.name,
                    suggested_manager: g.sugerido.map(PersonaResponse::from),
                })
                .collect(),
            blocked_resources: b.resources.iter().map(|r| r.resource_id).collect(),
            blocked_resources_detail: b.resources.into_iter().map(RecursoBloqueadoResponse::from).collect(),
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

/// Un recurso a transferir. `to` es el formato nuevo; `new_owner_user_id`
/// se sigue aceptando (equivale a `to: { type: "user" }`). Exactamente uno.
#[derive(Debug, Deserialize)]
pub struct OwnerTransferDto {
    pub resource_id: Uuid,
    #[serde(default)]
    pub new_owner_user_id: Option<Uuid>,
    #[serde(default)]
    pub to: Option<DestinoDto>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(tag = "type", content = "id", rename_all = "snake_case")]
pub enum DestinoDto {
    GroupAdmins(Uuid),
    Group(Uuid),
    User(Uuid),
}

impl From<DestinoPropiedad> for DestinoDto {
    fn from(d: DestinoPropiedad) -> Self {
        match d {
            DestinoPropiedad::AdminsDeGrupo(id) => Self::GroupAdmins(id),
            DestinoPropiedad::Grupo(id) => Self::Group(id),
            DestinoPropiedad::Usuario(id) => Self::User(id),
        }
    }
}

impl From<DestinoDto> for DestinoPropiedad {
    fn from(d: DestinoDto) -> Self {
        match d {
            DestinoDto::GroupAdmins(id) => Self::AdminsDeGrupo(id),
            DestinoDto::Group(id) => Self::Grupo(id),
            DestinoDto::User(id) => Self::Usuario(id),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ManagerTransferDto {
    pub group_id: Uuid,
    pub new_manager_user_id: Uuid,
}

impl TryFrom<TransferDto> for Transferencia {
    type Error = DomainError;

    fn try_from(t: TransferDto) -> Result<Self, Self::Error> {
        let owners = t
            .owners
            .into_iter()
            .map(|o| match (o.to, o.new_owner_user_id) {
                (Some(to), None) => Ok((o.resource_id, to.into())),
                (None, Some(user_id)) => Ok((o.resource_id, DestinoPropiedad::Usuario(user_id))),
                _ => Err(DomainError::ValidacionInvalida(
                    "cada transferencia de propiedad lleva `to` o `new_owner_user_id`, no ambos ni ninguno".into(),
                )),
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { owners, managers: t.managers.into_iter().map(|m| (m.group_id, m.new_manager_user_id)).collect() })
    }
}

#[derive(Debug, Serialize)]
pub struct PurgaResponse {
    pub resources_huerfanos_eliminados: u64,
}

#[derive(Debug, Deserialize)]
pub struct ActualizarActivoRequest {
    pub active: bool,
    /// Sólo al bloquear (`active: false`): transferencia opcional y parcial
    /// de lo que el usuario es único Owner, aplicada en la misma transacción.
    #[serde(default)]
    pub transfer: TransferDto,
}

/// `GET /admin/users` (F-29) — mismo patrón de página que `AuditLogPage`.
#[derive(Debug, Deserialize)]
pub struct ListarUsuariosQuery {
    pub cursor: Option<Uuid>,
    pub active: Option<bool>,
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct UsuariosPageResponse {
    pub items: Vec<UsuarioResponse>,
    pub next_cursor: Option<Uuid>,
}
