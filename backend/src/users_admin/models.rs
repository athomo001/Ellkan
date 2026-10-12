// Autor: Athan Espinoza

use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct GrupoBloqueado {
    pub group_id: Uuid,
    pub name: String,
    /// Miembro activo más antiguo del grupo (sin contar al saliente): el
    /// candidato que se sugiere promover a manager. `None` si no queda nadie.
    pub sugerido: Option<PersonaConAcceso>,
}

/// Alguien que ya tiene su propio `secret_envelope` del recurso — sólo a
/// esas personas se les puede dar la propiedad sin que nadie tenga que
/// sellarles el secreto (el servidor no puede hacerlo: nunca lo ve).
#[derive(Debug, Clone)]
pub struct PersonaConAcceso {
    pub user_id: Uuid,
    pub email: String,
    pub display_name: String,
}

#[derive(Debug, Clone)]
pub struct GrupoConAcceso {
    pub group_id: Uuid,
    pub name: String,
    pub level: String,
    /// Administradores activos del grupo que pueden recibir la propiedad.
    pub admins: Vec<PersonaConAcceso>,
    /// Miembros activos (sin contar al saliente) con acceso al recurso.
    pub miembros_con_acceso: i64,
}

#[derive(Debug, Clone)]
pub struct UsuarioConAcceso {
    pub persona: PersonaConAcceso,
    pub level: String,
}

/// A quién pasa la propiedad de un recurso cuyo único Owner sale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestinoPropiedad {
    /// Cada administrador activo del grupo recibe un permiso `owner`
    /// directo; el permiso del grupo no cambia (el resto sigue como estaba).
    AdminsDeGrupo(Uuid),
    /// El permiso del grupo sube a `owner`: todos sus miembros, también los
    /// que entren después, pueden editar, compartir y borrar.
    Grupo(Uuid),
    Usuario(Uuid),
}

/// Recurso donde el saliente es el único Owner y alguien más tiene acceso.
/// No lleva nombre: la metadata está cifrada y el servidor no la conoce.
#[derive(Debug, Clone)]
pub struct RecursoBloqueado {
    pub resource_id: Uuid,
    pub created_at: time::OffsetDateTime,
    pub grupos: Vec<GrupoConAcceso>,
    pub usuarios: Vec<UsuarioConAcceso>,
    /// Destino propuesto; `None` = nadie activo puede recibirlo.
    pub sugerencia: Option<DestinoPropiedad>,
}

#[derive(Debug, Clone, Default)]
pub struct Bloqueos {
    pub groups: Vec<GrupoBloqueado>,
    pub resources: Vec<RecursoBloqueado>,
}

impl Bloqueos {
    pub fn vacio(&self) -> bool {
        self.groups.is_empty() && self.resources.is_empty()
    }
}

#[derive(Debug, Clone, Default)]
pub struct Transferencia {
    pub owners: Vec<(Uuid, DestinoPropiedad)>,
    pub managers: Vec<(Uuid, Uuid)>,
}

impl Transferencia {
    pub fn vacia(&self) -> bool {
        self.owners.is_empty() && self.managers.is_empty()
    }
}

/// Lo que efectivamente cambió por cada recurso, para auditarlo.
#[derive(Debug, Clone)]
pub struct RecursoTransferido {
    pub resource_id: Uuid,
    pub destino: DestinoPropiedad,
    pub nuevos_owners: usize,
}

#[derive(Debug, Clone, Default)]
pub struct ResultadoPurgaUsuario {
    pub resources_huerfanos_eliminados: u64,
    pub transferidos: Vec<RecursoTransferido>,
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

fn rango_nivel(level: &str) -> u8 {
    match level {
        "owner" => 2,
        "update" => 1,
        _ => 0,
    }
}

/// Destino que se le propone al admin para un recurso bloqueado — nunca se
/// aplica solo: el admin lo confirma o lo cambia. Prioridad:
/// 1. los administradores del grupo con más nivel sobre el recurso (a igual
///    nivel, el primero por nombre): quedan como propietarios sin abrirle
///    el borrado a todo el grupo;
/// 2. si ningún grupo tiene administradores activos, el grupo con más nivel
///    que tenga algún miembro activo;
/// 3. si no hay grupos utilizables, el usuario directo con más nivel;
/// 4. `None`: nadie activo puede recibirlo.
pub fn sugerir_destino(grupos: &[GrupoConAcceso], usuarios: &[UsuarioConAcceso]) -> Option<DestinoPropiedad> {
    let mut ordenados: Vec<&GrupoConAcceso> = grupos.iter().collect();
    ordenados.sort_by(|a, b| rango_nivel(&b.level).cmp(&rango_nivel(&a.level)).then_with(|| a.name.cmp(&b.name)));

    if let Some(g) = ordenados.iter().find(|g| !g.admins.is_empty()) {
        return Some(DestinoPropiedad::AdminsDeGrupo(g.group_id));
    }
    if let Some(g) = ordenados.iter().find(|g| g.miembros_con_acceso > 0) {
        return Some(DestinoPropiedad::Grupo(g.group_id));
    }
    usuarios
        .iter()
        .max_by_key(|u| rango_nivel(&u.level))
        .map(|u| DestinoPropiedad::Usuario(u.persona.user_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn persona() -> PersonaConAcceso {
        PersonaConAcceso { user_id: Uuid::now_v7(), email: "a@b.c".into(), display_name: "A".into() }
    }

    fn grupo(name: &str, level: &str, con_admin: bool, miembros: i64) -> GrupoConAcceso {
        GrupoConAcceso {
            group_id: Uuid::now_v7(),
            name: name.into(),
            level: level.into(),
            admins: if con_admin { vec![persona()] } else { vec![] },
            miembros_con_acceso: miembros,
        }
    }

    #[test]
    fn prefiere_los_admins_del_grupo_con_mas_nivel() {
        let lectura = grupo("A-lectura", "read", true, 3);
        let edicion = grupo("Z-edicion", "update", true, 3);
        let destino = sugerir_destino(&[lectura, edicion.clone()], &[]);
        assert_eq!(destino, Some(DestinoPropiedad::AdminsDeGrupo(edicion.group_id)));
    }

    #[test]
    fn a_igual_nivel_desempata_por_nombre() {
        let b = grupo("N2", "read", true, 4);
        let a = grupo("CDC-Analistas", "read", true, 6);
        let destino = sugerir_destino(&[b, a.clone()], &[]);
        assert_eq!(destino, Some(DestinoPropiedad::AdminsDeGrupo(a.group_id)));
    }

    #[test]
    fn sin_admins_activos_propone_el_grupo_entero() {
        let g = grupo("Soporte", "read", false, 2);
        assert_eq!(sugerir_destino(std::slice::from_ref(&g), &[]), Some(DestinoPropiedad::Grupo(g.group_id)));
    }

    #[test]
    fn sin_grupos_utilizables_propone_un_usuario() {
        let vacio = grupo("Vacio", "update", false, 0);
        let u = UsuarioConAcceso { persona: persona(), level: "read".into() };
        let destino = sugerir_destino(&[vacio], std::slice::from_ref(&u));
        assert_eq!(destino, Some(DestinoPropiedad::Usuario(u.persona.user_id)));
    }

    #[test]
    fn sin_nadie_activo_no_hay_sugerencia() {
        assert_eq!(sugerir_destino(&[grupo("Vacio", "read", false, 0)], &[]), None);
    }
}
