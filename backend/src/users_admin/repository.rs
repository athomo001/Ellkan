// Autor: Athan Espinoza

#![allow(async_fn_in_trait)]

use std::collections::HashMap;

use uuid::Uuid;

use crate::error::RepoError;

use super::models::{
    sugerir_destino, Bloqueos, DestinoPropiedad, GrupoBloqueado, GrupoConAcceso, PersonaConAcceso, RecursoBloqueado,
    RecursoTransferido, ResultadoPurgaUsuario, ResumenUsuario, Transferencia, UsuarioConAcceso,
};

/// Alcance documentado: la detección de "único Owner" resuelve sólo
/// ownership *directa* (`permissions.grantee_type = 'user'`) — ownership
/// indirecta vía un grupo del que el usuario sea el único manager queda
/// fuera de este primer corte (el propio bloqueo de grupo ya cubre el caso
/// más común: sin manager, nadie administra ese acceso de grupo de todos
/// modos). Documentado como límite real, no oculto — mismo criterio que el
/// resto de las simplificaciones de esta fase.
pub trait UserPurgeRepository {
    async fn calcular_bloqueos(&self, user_id: Uuid) -> Result<Bloqueos, RepoError>;

    async fn activo_y_existe(&self, user_id: Uuid) -> Result<bool, RepoError>;

    /// Ejecuta la purga completa dentro de una única transacción: valida de
    /// nuevo los bloqueos (contra una posible carrera desde el dry-run),
    /// aplica las transferencias, borra los permisos propios, borra al
    /// usuario (cascada real sobre sus propias filas), y por último borra
    /// los recursos que quedaron sin ningún `secret_envelope` — devuelve
    /// `Err(RepoError::Conflict)` si la transferencia no cubre el 100% de
    /// lo bloqueante o si algún destino no es válido.
    async fn purgar(&self, user_id: Uuid, transferencia: &Transferencia) -> Result<ResultadoPurgaUsuario, RepoError>;

    async fn obtener_resumen(&self, user_id: Uuid) -> Result<Option<ResumenUsuario>, RepoError>;

    /// F-40 (tercer checkbox): `active=false` + rotar `security_stamp` en
    /// la misma sentencia — `SessionRepository::validar` exige
    /// `sessions.security_stamp = users.security_stamp`, así que rotarlo
    /// invalida toda sesión abierta de una sola vez, sin iterarlas (mismo
    /// mecanismo que ya usa F-02 para invalidación masiva).
    async fn desactivar(&self, user_id: Uuid) -> Result<bool, RepoError>;

    /// Como `desactivar`, pero aplicando antes, en la misma transacción, una
    /// transferencia **opcional y parcial** (al bloquear no hace falta cubrir
    /// todo: puede ser una suspensión temporal). La transferencia sólo suma
    /// propietarios; el usuario bloqueado conserva los suyos por si se lo
    /// reactiva. `None` = el usuario no existía o ya estaba inactivo.
    async fn desactivar_con_transferencia(
        &self,
        user_id: Uuid,
        transferencia: &Transferencia,
    ) -> Result<Option<Vec<RecursoTransferido>>, RepoError>;

    async fn activar(&self, user_id: Uuid) -> Result<bool, RepoError>;

    /// `GET /admin/users` (F-29) — keyset pagination por `id desc`, mismo
    /// patrón que `audit::repository::listar` (`users.id` es `uuidv7`,
    /// monótono con `created_at`, no hace falta cursor compuesto).
    async fn listar(&self, active: Option<bool>, cursor: Option<Uuid>, limite: i64) -> Result<Vec<ResumenUsuario>, RepoError>;
}

#[derive(Clone)]
pub struct PgUserPurgeRepository {
    pub pool: sqlx::PgPool,
}


/// Grupos donde el saliente es el único manager y queda alguien más, con el
/// miembro activo más antiguo como candidato sugerido a manager.
async fn grupos_bloqueados_en(user_id: Uuid, con: &mut sqlx::PgConnection) -> Result<Vec<GrupoBloqueado>, RepoError> {
    // Sólo bloquea si el grupo tiene OTRO miembro (admin o no) que se
    // quedaría sin nadie que lo administre — un grupo donde este
    // usuario es el único miembro de punta a punta no bloquea nada
    // (mismo criterio que para recursos: bloquear sólo cuando dejar de
    // existir este usuario afecta a alguien más).
    let grupos = sqlx::query!(
        r#"
        select g.id, g.name
        from group_members gm
        join groups g on g.id = gm.group_id and g.deleted_at is null
        where gm.user_id = $1 and gm.is_admin
          and not exists (
              select 1 from group_members gm2
              where gm2.group_id = gm.group_id and gm2.is_admin and gm2.user_id <> $1
          )
          and exists (
              select 1 from group_members gm3
              where gm3.group_id = gm.group_id and gm3.user_id <> $1
          )
        "#,
        user_id,
    )
    .fetch_all(&mut *con)
    .await?;
    if grupos.is_empty() {
        return Ok(Vec::new());
    }

    let ids: Vec<Uuid> = grupos.iter().map(|g| g.id).collect();
    let sugeridos = sqlx::query!(
        r#"
        select distinct on (gm.group_id) gm.group_id, u.id as user_id, u.email, u.display_name
        from group_members gm
        join users u on u.id = gm.user_id and u.active and u.deleted_at is null
        where gm.group_id = any($1) and gm.user_id <> $2
        order by gm.group_id, gm.created_at, u.id
        "#,
        &ids[..],
        user_id,
    )
    .fetch_all(&mut *con)
    .await?;

    Ok(grupos
        .into_iter()
        .map(|g| GrupoBloqueado {
            group_id: g.id,
            sugerido: sugeridos.iter().find(|s| s.group_id == g.id).map(|s| PersonaConAcceso {
                user_id: s.user_id,
                email: s.email.clone(),
                display_name: s.display_name.clone(),
            }),
            name: g.name,
        })
        .collect())
}

/// Un recurso sólo bloquea si el saliente es su **único** Owner y **alguien
/// más** (otro usuario u otro grupo) tiene algún acceso real sobre él. Si
/// nadie más tiene acceso, el recurso queda huérfano y `purgar()` lo borra
/// solo; si ya hay otro Owner (por ejemplo, porque se transfirió al
/// bloquearlo), no hace falta transferir nada más.
async fn recursos_bloqueados_en(user_id: Uuid, con: &mut sqlx::PgConnection) -> Result<Vec<Uuid>, RepoError> {
    let filas = sqlx::query!(
        r#"
        select p.subject_id as resource_id
        from permissions p
        join resources r on r.id = p.subject_id and r.deleted_at is null
        where p.subject_type = 'resource' and p.grantee_type = 'user' and p.grantee_id = $1 and p.level = 'owner'
          and exists (
              select 1 from permissions p2
              where p2.subject_type = 'resource' and p2.subject_id = p.subject_id
                and not (p2.grantee_type = 'user' and p2.grantee_id = $1)
          )
          and not exists (
              select 1 from permissions p3
              where p3.subject_type = 'resource' and p3.subject_id = p.subject_id and p3.level = 'owner'
                and not (p3.grantee_type = 'user' and p3.grantee_id = $1)
          )
        order by p.subject_id
        "#,
        user_id,
    )
    .fetch_all(&mut *con)
    .await?;
    Ok(filas.into_iter().map(|f| f.resource_id).collect())
}

/// Para cada recurso bloqueado: con qué grupos y usuarios está compartido y
/// quiénes pueden recibir la propiedad. Sólo cuenta a personas activas que
/// ya tienen su `secret_envelope` del recurso.
async fn detalle_de(user_id: Uuid, ids: &[Uuid], con: &mut sqlx::PgConnection) -> Result<Vec<RecursoBloqueado>, RepoError> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }

    let creados = sqlx::query!(r#"select id, created_at from resources where id = any($1)"#, ids)
        .fetch_all(&mut *con)
        .await?;

    let grupos = sqlx::query!(
        r#"
        select p.subject_id as resource_id, g.id as group_id, g.name, p.level,
            (
                select count(*) from group_members gm
                join users u on u.id = gm.user_id and u.active and u.deleted_at is null
                where gm.group_id = g.id and gm.user_id <> $2
                  and exists (select 1 from secret_envelopes se where se.resource_id = p.subject_id and se.user_id = gm.user_id)
            ) as "miembros_con_acceso!"
        from permissions p
        join groups g on g.id = p.grantee_id and g.deleted_at is null
        where p.subject_type = 'resource' and p.grantee_type = 'group' and p.subject_id = any($1)
        order by g.name
        "#,
        ids,
        user_id,
    )
    .fetch_all(&mut *con)
    .await?;

    let admins = sqlx::query!(
        r#"
        select p.subject_id as resource_id, gm.group_id, u.id as user_id, u.email, u.display_name
        from permissions p
        join group_members gm on gm.group_id = p.grantee_id and gm.is_admin
        join users u on u.id = gm.user_id and u.active and u.deleted_at is null
        where p.subject_type = 'resource' and p.grantee_type = 'group' and p.subject_id = any($1)
          and gm.user_id <> $2
          and exists (select 1 from secret_envelopes se where se.resource_id = p.subject_id and se.user_id = gm.user_id)
        order by u.display_name, u.email
        "#,
        ids,
        user_id,
    )
    .fetch_all(&mut *con)
    .await?;

    let usuarios = sqlx::query!(
        r#"
        select p.subject_id as resource_id, u.id as user_id, u.email, u.display_name, p.level
        from permissions p
        join users u on u.id = p.grantee_id and u.active and u.deleted_at is null
        where p.subject_type = 'resource' and p.grantee_type = 'user' and p.subject_id = any($1)
          and p.grantee_id <> $2
          and exists (select 1 from secret_envelopes se where se.resource_id = p.subject_id and se.user_id = u.id)
        order by u.display_name, u.email
        "#,
        ids,
        user_id,
    )
    .fetch_all(&mut *con)
    .await?;

    let mut por_recurso: HashMap<Uuid, RecursoBloqueado> = creados
        .into_iter()
        .map(|c| {
            let recurso =
                RecursoBloqueado { resource_id: c.id, created_at: c.created_at, grupos: Vec::new(), usuarios: Vec::new(), sugerencia: None };
            (c.id, recurso)
        })
        .collect();

    for g in grupos {
        let Some(recurso) = por_recurso.get_mut(&g.resource_id) else { continue };
        let admins_del_grupo = admins
            .iter()
            .filter(|a| a.resource_id == g.resource_id && a.group_id == g.group_id)
            .map(|a| PersonaConAcceso { user_id: a.user_id, email: a.email.clone(), display_name: a.display_name.clone() })
            .collect();
        recurso.grupos.push(GrupoConAcceso {
            group_id: g.group_id,
            name: g.name,
            level: g.level,
            admins: admins_del_grupo,
            miembros_con_acceso: g.miembros_con_acceso,
        });
    }
    for u in usuarios {
        let Some(recurso) = por_recurso.get_mut(&u.resource_id) else { continue };
        recurso.usuarios.push(UsuarioConAcceso {
            persona: PersonaConAcceso { user_id: u.user_id, email: u.email, display_name: u.display_name },
            level: u.level,
        });
    }

    // Mismo orden que `ids`: estable entre llamadas.
    Ok(ids
        .iter()
        .filter_map(|id| por_recurso.remove(id))
        .map(|mut r| {
            r.sugerencia = sugerir_destino(&r.grupos, &r.usuarios);
            r
        })
        .collect())
}

/// Da permiso `owner` directo a un usuario, o sube a `owner` el que ya tenía.
async fn hacer_owner_directo(resource_id: Uuid, user_id: Uuid, con: &mut sqlx::PgConnection) -> Result<(), RepoError> {
    sqlx::query!(
        r#"
        insert into permissions (subject_type, subject_id, grantee_type, grantee_id, level)
        values ('resource', $1, 'user', $2, 'owner')
        on conflict (subject_type, subject_id, grantee_type, grantee_id) do update set level = 'owner'
        "#,
        resource_id,
        user_id,
    )
    .execute(&mut *con)
    .await?;
    Ok(())
}

/// Aplica la transferencia de propiedad. Cualquier destino inválido aborta
/// todo con `Conflict` (la transacción del llamador hace el rollback):
/// - sólo se transfieren recursos que de verdad bloquean (`bloqueados`): un
///   admin no puede usar esto para darle la propiedad de cualquier recurso
///   a quien quiera;
/// - nunca se le da la propiedad a quien no tiene su propio
///   `secret_envelope`: no hay forma zero-knowledge de sellárselo acá.
async fn aplicar_owners(
    user_id: Uuid,
    owners: &[(Uuid, DestinoPropiedad)],
    bloqueados: &[Uuid],
    con: &mut sqlx::PgConnection,
) -> Result<Vec<RecursoTransferido>, RepoError> {
    let mut transferidos = Vec::with_capacity(owners.len());
    for &(resource_id, destino) in owners {
        if !bloqueados.contains(&resource_id) {
            return Err(RepoError::Conflict);
        }
        let nuevos_owners = match destino {
            DestinoPropiedad::Usuario(nuevo) => {
                if nuevo == user_id {
                    return Err(RepoError::Conflict);
                }
                let valido = sqlx::query!(
                    r#"
                    select 1 as "existe!" from users u
                    join secret_envelopes se on se.user_id = u.id and se.resource_id = $1
                    where u.id = $2 and u.active and u.deleted_at is null
                    "#,
                    resource_id,
                    nuevo,
                )
                .fetch_optional(&mut *con)
                .await?;
                if valido.is_none() {
                    return Err(RepoError::Conflict);
                }
                hacer_owner_directo(resource_id, nuevo, con).await?;
                1
            }
            DestinoPropiedad::AdminsDeGrupo(group_id) => {
                let admins = sqlx::query!(
                    r#"
                    select gm.user_id
                    from permissions p
                    join groups g on g.id = p.grantee_id and g.deleted_at is null
                    join group_members gm on gm.group_id = g.id and gm.is_admin
                    join users u on u.id = gm.user_id and u.active and u.deleted_at is null
                    where p.subject_type = 'resource' and p.subject_id = $1
                      and p.grantee_type = 'group' and p.grantee_id = $2
                      and gm.user_id <> $3
                      and exists (select 1 from secret_envelopes se where se.resource_id = $1 and se.user_id = gm.user_id)
                    "#,
                    resource_id,
                    group_id,
                    user_id,
                )
                .fetch_all(&mut *con)
                .await?;
                if admins.is_empty() {
                    return Err(RepoError::Conflict);
                }
                for admin in &admins {
                    hacer_owner_directo(resource_id, admin.user_id, con).await?;
                }
                admins.len()
            }
            DestinoPropiedad::Grupo(group_id) => {
                let miembros: i64 = sqlx::query!(
                    r#"
                    select count(*) as "n!"
                    from permissions p
                    join groups g on g.id = p.grantee_id and g.deleted_at is null
                    join group_members gm on gm.group_id = g.id
                    join users u on u.id = gm.user_id and u.active and u.deleted_at is null
                    where p.subject_type = 'resource' and p.subject_id = $1
                      and p.grantee_type = 'group' and p.grantee_id = $2
                      and gm.user_id <> $3
                      and exists (select 1 from secret_envelopes se where se.resource_id = $1 and se.user_id = gm.user_id)
                    "#,
                    resource_id,
                    group_id,
                    user_id,
                )
                .fetch_one(&mut *con)
                .await?
                .n;
                if miembros == 0 {
                    return Err(RepoError::Conflict);
                }
                let resultado = sqlx::query!(
                    r#"
                    update permissions set level = 'owner'
                    where subject_type = 'resource' and subject_id = $1 and grantee_type = 'group' and grantee_id = $2
                    "#,
                    resource_id,
                    group_id,
                )
                .execute(&mut *con)
                .await?;
                if resultado.rows_affected() != 1 {
                    return Err(RepoError::Conflict);
                }
                miembros as usize
            }
        };
        transferidos.push(RecursoTransferido { resource_id, destino, nuevos_owners });
    }
    Ok(transferidos)
}

async fn aplicar_managers(user_id: Uuid, managers: &[(Uuid, Uuid)], con: &mut sqlx::PgConnection) -> Result<(), RepoError> {
    for &(group_id, nuevo_manager) in managers {
        if nuevo_manager == user_id {
            return Err(RepoError::Conflict);
        }
        let resultado = sqlx::query!(
            r#"update group_members set is_admin = true where group_id = $1 and user_id = $2"#,
            group_id,
            nuevo_manager,
        )
        .execute(&mut *con)
        .await?;
        if resultado.rows_affected() != 1 {
            // El destinatario no era miembro del grupo — no se puede
            // promover a alguien que ni siquiera pertenece a él.
            return Err(RepoError::Conflict);
        }
    }
    Ok(())
}

impl UserPurgeRepository for PgUserPurgeRepository {
    async fn calcular_bloqueos(&self, user_id: Uuid) -> Result<Bloqueos, RepoError> {
        let mut con = self.pool.acquire().await?;
        let groups = grupos_bloqueados_en(user_id, &mut con).await?;
        let ids = recursos_bloqueados_en(user_id, &mut con).await?;
        let resources = detalle_de(user_id, &ids, &mut con).await?;
        Ok(Bloqueos { groups, resources })
    }

    async fn activo_y_existe(&self, user_id: Uuid) -> Result<bool, RepoError> {
        let fila = sqlx::query!(r#"select 1 as "existe!" from users where id = $1"#, user_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(fila.is_some())
    }

    async fn purgar(&self, user_id: Uuid, transferencia: &Transferencia) -> Result<ResultadoPurgaUsuario, RepoError> {
        let mut tx = self.pool.begin().await?;

        let bloqueos_grupos = grupos_bloqueados_en(user_id, &mut tx).await?;
        let bloqueos_recursos = recursos_bloqueados_en(user_id, &mut tx).await?;

        let cubre_grupos = bloqueos_grupos
            .iter()
            .all(|b| transferencia.managers.iter().any(|(g, _)| *g == b.group_id));
        let cubre_recursos = bloqueos_recursos
            .iter()
            .all(|r| transferencia.owners.iter().any(|(res, _)| res == r));
        if !cubre_grupos || !cubre_recursos {
            return Err(RepoError::Conflict);
        }

        // H-32 (auditoría 2026-08-12): cada paso de la transferencia revisa
        // que realmente cambió una fila; una purga concurrente del destino
        // hace fallar todo en vez de reportar un éxito que no ocurrió.
        let transferidos = aplicar_owners(user_id, &transferencia.owners, &bloqueos_recursos, &mut tx).await?;
        aplicar_managers(user_id, &transferencia.managers, &mut tx).await?;

        // Recursos donde el usuario purgado era el único con un
        // `secret_envelope` — se determinan ANTES de borrar al usuario
        // (la cascada todavía no corrió), se eliminan DESPUÉS (para que la
        // cascada ya haya limpiado su propia fila y esta query no se pise
        // con ella).
        let huerfanos = sqlx::query!(
            r#"
            select se.resource_id
            from secret_envelopes se
            where se.user_id = $1
              and not exists (
                  select 1 from secret_envelopes se2
                  where se2.resource_id = se.resource_id and se2.user_id <> $1
              )
            "#,
            user_id,
        )
        .fetch_all(&mut *tx)
        .await?;
        let huerfanos: Vec<Uuid> = huerfanos.into_iter().map(|f| f.resource_id).collect();

        sqlx::query!(
            r#"delete from permissions where grantee_type = 'user' and grantee_id = $1"#,
            user_id,
        )
        .execute(&mut *tx)
        .await?;

        sqlx::query!(r#"delete from users where id = $1"#, user_id).execute(&mut *tx).await?;

        sqlx::query!(r#"delete from resource_tags where resource_id = any($1)"#, &huerfanos[..])
            .execute(&mut *tx)
            .await?;
        sqlx::query!(r#"delete from folder_items where resource_id = any($1)"#, &huerfanos[..])
            .execute(&mut *tx)
            .await?;
        let r = sqlx::query!(r#"delete from resources where id = any($1)"#, &huerfanos[..])
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(ResultadoPurgaUsuario { resources_huerfanos_eliminados: r.rows_affected(), transferidos })
    }

    async fn desactivar_con_transferencia(
        &self,
        user_id: Uuid,
        transferencia: &Transferencia,
    ) -> Result<Option<Vec<RecursoTransferido>>, RepoError> {
        let mut tx = self.pool.begin().await?;

        let bloqueados = recursos_bloqueados_en(user_id, &mut tx).await?;
        let transferidos = aplicar_owners(user_id, &transferencia.owners, &bloqueados, &mut tx).await?;
        aplicar_managers(user_id, &transferencia.managers, &mut tx).await?;

        let resultado = sqlx::query!(
            r#"update users set active = false, security_stamp = gen_random_uuid()
               where id = $1 and deleted_at is null and active"#,
            user_id,
        )
        .execute(&mut *tx)
        .await?;
        if resultado.rows_affected() != 1 {
            tx.rollback().await?;
            return Ok(None);
        }

        tx.commit().await?;
        Ok(Some(transferidos))
    }

    async fn obtener_resumen(&self, user_id: Uuid) -> Result<Option<ResumenUsuario>, RepoError> {
        let fila = sqlx::query!(
            r#"
            select
                u.id, u.email, u.display_name, u.active,
                (u.avatar_content_type is not null) as "has_avatar!",
                coalesce((
                    select array_agg(g.name order by g.name)
                    from group_members gm join groups g on g.id = gm.group_id
                    where gm.user_id = u.id and g.deleted_at is null
                ), '{}') as "groups!: Vec<String>",
                (select count(*) from resources r where r.created_by = u.id) as "owned_resources_count!",
                (
                    select count(*) from permissions p
                    join resources r on r.id = p.subject_id
                    where p.subject_type = 'resource' and p.grantee_type = 'user' and p.grantee_id = u.id
                      and r.created_by is distinct from u.id
                ) as "shared_with_count!"
            from users u
            where u.id = $1 and u.deleted_at is null
            "#,
            user_id,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(fila.map(|f| ResumenUsuario {
            id: f.id,
            email: f.email,
            display_name: f.display_name,
            active: f.active,
            has_avatar: f.has_avatar,
            groups: f.groups,
            owned_resources_count: f.owned_resources_count,
            shared_with_count: f.shared_with_count,
        }))
    }

    async fn desactivar(&self, user_id: Uuid) -> Result<bool, RepoError> {
        let resultado = sqlx::query!(
            r#"update users set active = false, security_stamp = gen_random_uuid()
               where id = $1 and deleted_at is null and active"#,
            user_id,
        )
        .execute(&self.pool)
        .await?;
        Ok(resultado.rows_affected() == 1)
    }

    async fn activar(&self, user_id: Uuid) -> Result<bool, RepoError> {
        let resultado = sqlx::query!(
            r#"update users set active = true where id = $1 and deleted_at is null and not active"#,
            user_id,
        )
        .execute(&self.pool)
        .await?;
        Ok(resultado.rows_affected() == 1)
    }

    async fn listar(&self, active: Option<bool>, cursor: Option<Uuid>, limite: i64) -> Result<Vec<ResumenUsuario>, RepoError> {
        // F-29/post-cierre bloque C: subqueries escalares en vez de JOIN+GROUP
        // BY — más simple de mantener correcto junto al `limit`/`order by` de
        // la paginación, y sigue siendo una sola query (no N+1 por usuario).
        let filas = sqlx::query!(
            r#"
            select
                u.id, u.email, u.display_name, u.active,
                (u.avatar_content_type is not null) as "has_avatar!",
                coalesce((
                    select array_agg(g.name order by g.name)
                    from group_members gm join groups g on g.id = gm.group_id
                    where gm.user_id = u.id and g.deleted_at is null
                ), '{}') as "groups!: Vec<String>",
                (select count(*) from resources r where r.created_by = u.id) as "owned_resources_count!",
                (
                    select count(*) from permissions p
                    join resources r on r.id = p.subject_id
                    where p.subject_type = 'resource' and p.grantee_type = 'user' and p.grantee_id = u.id
                      and r.created_by is distinct from u.id
                ) as "shared_with_count!"
            from users u
            where u.deleted_at is null
              and ($1::uuid is null or u.id < $1)
              and ($2::bool is null or u.active = $2)
            order by u.id desc
            limit $3
            "#,
            cursor,
            active,
            limite,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(filas
            .into_iter()
            .map(|f| ResumenUsuario {
                id: f.id,
                email: f.email,
                display_name: f.display_name,
                active: f.active,
                has_avatar: f.has_avatar,
                groups: f.groups,
                owned_resources_count: f.owned_resources_count,
                shared_with_count: f.shared_with_count,
            })
            .collect())
    }
}
