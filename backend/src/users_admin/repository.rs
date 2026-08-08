// Autor: Athan Espinoza

#![allow(async_fn_in_trait)]

use uuid::Uuid;

use crate::error::RepoError;

use super::models::{Bloqueos, GrupoBloqueado, ResultadoPurgaUsuario, ResumenUsuario};

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
    /// lo bloqueante.
    async fn purgar(&self, user_id: Uuid, transferencia: &super::models::Transferencia) -> Result<ResultadoPurgaUsuario, RepoError>;

    async fn obtener_resumen(&self, user_id: Uuid) -> Result<Option<ResumenUsuario>, RepoError>;

    /// F-40 (tercer checkbox): `active=false` + rotar `security_stamp` en
    /// la misma sentencia — `SessionRepository::validar` exige
    /// `sessions.security_stamp = users.security_stamp`, así que rotarlo
    /// invalida toda sesión abierta de una sola vez, sin iterarlas (mismo
    /// mecanismo que ya usa F-02 para invalidación masiva).
    async fn desactivar(&self, user_id: Uuid) -> Result<bool, RepoError>;

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

impl PgUserPurgeRepository {
    async fn bloqueos_en<'e, E>(&self, user_id: Uuid, ejecutor: E) -> Result<Bloqueos, RepoError>
    where
        E: sqlx::PgExecutor<'e>,
    {
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
            "#,
            user_id,
        )
        .fetch_all(ejecutor)
        .await?;

        Ok(Bloqueos {
            groups: grupos.into_iter().map(|f| GrupoBloqueado { group_id: f.id, name: f.name }).collect(),
            // El resto de la función se completa afuera (dos ejecutores
            // distintos por préstamo — ver `calcular_bloqueos`).
            resources: Vec::new(),
        })
    }

    async fn resources_bloqueados_en<'e, E>(&self, user_id: Uuid, ejecutor: E) -> Result<Vec<Uuid>, RepoError>
    where
        E: sqlx::PgExecutor<'e>,
    {
        let filas = sqlx::query!(
            r#"
            select p.subject_id as resource_id
            from permissions p
            join resources r on r.id = p.subject_id and r.deleted_at is null
            where p.subject_type = 'resource' and p.grantee_type = 'user' and p.grantee_id = $1 and p.level = 'owner'
              and not exists (
                  select 1 from permissions p2
                  where p2.subject_type = 'resource' and p2.subject_id = p.subject_id
                    and p2.level = 'owner' and p2.grantee_type = 'user' and p2.grantee_id <> $1
              )
            "#,
            user_id,
        )
        .fetch_all(ejecutor)
        .await?;
        Ok(filas.into_iter().map(|f| f.resource_id).collect())
    }
}

impl UserPurgeRepository for PgUserPurgeRepository {
    async fn calcular_bloqueos(&self, user_id: Uuid) -> Result<Bloqueos, RepoError> {
        let mut bloqueos = self.bloqueos_en(user_id, &self.pool).await?;
        bloqueos.resources = self.resources_bloqueados_en(user_id, &self.pool).await?;
        Ok(bloqueos)
    }

    async fn activo_y_existe(&self, user_id: Uuid) -> Result<bool, RepoError> {
        let fila = sqlx::query!(r#"select 1 as "existe!" from users where id = $1"#, user_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(fila.is_some())
    }

    async fn purgar(&self, user_id: Uuid, transferencia: &super::models::Transferencia) -> Result<ResultadoPurgaUsuario, RepoError> {
        let mut tx = self.pool.begin().await?;

        let bloqueos_grupos = self.bloqueos_en(user_id, &mut *tx).await?.groups;
        let bloqueos_recursos = self.resources_bloqueados_en(user_id, &mut *tx).await?;

        let cubre_grupos = bloqueos_grupos
            .iter()
            .all(|b| transferencia.managers.iter().any(|(g, _)| *g == b.group_id));
        let cubre_recursos = bloqueos_recursos
            .iter()
            .all(|r| transferencia.owners.iter().any(|(res, _)| res == r));
        if !cubre_grupos || !cubre_recursos {
            return Err(RepoError::Conflict);
        }

        for (resource_id, nuevo_owner) in &transferencia.owners {
            let tiene_acceso = sqlx::query!(
                r#"
                select 1 as "existe!" from permissions
                where subject_type = 'resource' and subject_id = $1 and grantee_type = 'user' and grantee_id = $2
                "#,
                resource_id,
                nuevo_owner,
            )
            .fetch_optional(&mut *tx)
            .await?;
            if tiene_acceso.is_none() {
                // El destinatario no tiene ya un `secret_envelope` propio en
                // este recurso — no hay forma zero-knowledge de convertirlo
                // en Owner sin que alguien lo selle para él primero.
                return Err(RepoError::Conflict);
            }

            sqlx::query!(
                r#"
                update permissions set level = 'owner'
                where subject_type = 'resource' and subject_id = $1 and grantee_type = 'user' and grantee_id = $2
                "#,
                resource_id,
                nuevo_owner,
            )
            .execute(&mut *tx)
            .await?;
        }

        for (group_id, nuevo_manager) in &transferencia.managers {
            let resultado = sqlx::query!(
                r#"update group_members set is_admin = true where group_id = $1 and user_id = $2"#,
                group_id,
                nuevo_manager,
            )
            .execute(&mut *tx)
            .await?;
            if resultado.rows_affected() != 1 {
                // El destinatario no era miembro del grupo — no se puede
                // promover a alguien que ni siquiera pertenece a él.
                return Err(RepoError::Conflict);
            }
        }

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
        Ok(ResultadoPurgaUsuario { resources_huerfanos_eliminados: r.rows_affected() })
    }

    async fn obtener_resumen(&self, user_id: Uuid) -> Result<Option<ResumenUsuario>, RepoError> {
        let fila = sqlx::query!(
            r#"select id, email, display_name, active from users where id = $1 and deleted_at is null"#,
            user_id,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(fila.map(|f| ResumenUsuario { id: f.id, email: f.email, display_name: f.display_name, active: f.active }))
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
        let filas = sqlx::query!(
            r#"
            select id, email, display_name, active
            from users
            where deleted_at is null
              and ($1::uuid is null or id < $1)
              and ($2::bool is null or active = $2)
            order by id desc
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
            .map(|f| ResumenUsuario { id: f.id, email: f.email, display_name: f.display_name, active: f.active })
            .collect())
    }
}
