// Autor: Athan Espinoza

#![allow(async_fn_in_trait)]

use uuid::Uuid;

use crate::error::RepoError;

use super::models::{EnvelopeParaMiembroNuevo, Group, GrupoDeUsuario, Miembro};

pub trait GroupRepository {
    async fn crear(&self, id: Uuid, name: &str, parent_group_id: Option<Uuid>) -> Result<Group, RepoError>;

    async fn buscar(&self, id: Uuid) -> Result<Option<Group>, RepoError>;

    async fn hijos_directos(&self, group_id: Uuid) -> Result<Vec<Group>, RepoError>;

    async fn raices(&self) -> Result<Vec<Group>, RepoError>;

    async fn tiene_hijos(&self, group_id: Uuid) -> Result<bool, RepoError>;

    /// `group_id` y todos sus ancestros hasta la raíz, inclusive — usado
    /// tanto para resolver autoridad delegada recursiva como para detectar
    /// ciclos en un re-parenting.
    async fn ancestros_inclusive(&self, group_id: Uuid) -> Result<Vec<Uuid>, RepoError>;

    /// Profundidad de `group_id` en su árbol — raíz = 1.
    async fn profundidad(&self, group_id: Uuid) -> Result<i32, RepoError>;

    async fn mover(&self, group_id: Uuid, new_parent_group_id: Option<Uuid>) -> Result<(), RepoError>;

    async fn eliminar(&self, group_id: Uuid) -> Result<(), RepoError>;

    /// 2026-08-13: sólo tocable por un admin de organización — el handler
    /// gatea con `AdminUser`, no hay chequeo de autoridad acá adentro.
    async fn actualizar_share_exempt(&self, group_id: Uuid, exempt: bool) -> Result<(), RepoError>;

    /// F-19: find-or-create por nombre a nivel raíz, usado por Directory
    /// Sync para auto-crear grupos que vienen del directorio (`memberOf`).
    /// Si ya existe un grupo raíz con ese nombre (armado a mano o por una
    /// corrida anterior), reusa su `id` sin tocar `managed_by_directory_sync`
    /// — sólo se marca `true` en la creación real, nunca se le pisa el flag
    /// a un grupo que ya existía por otra vía.
    async fn buscar_o_crear_raiz_gestionado(&self, name: &str) -> Result<Uuid, RepoError>;
}

pub trait GroupMemberRepository {
    async fn agregar_simple(&self, group_id: Uuid, user_id: Uuid, is_admin: bool) -> Result<(), RepoError>;

    /// F-12: agregar a alguien a un grupo que ya comparte recursos exige
    /// sellarle la DEK de cada uno — todo en una transacción: si algo falla,
    /// no queda a medias (ni el miembro sin sus envelopes, ni envelopes
    /// huérfanos sin el miembro).
    async fn agregar_con_envelopes(
        &self,
        group_id: Uuid,
        user_id: Uuid,
        is_admin: bool,
        envelopes: &[EnvelopeParaMiembroNuevo],
    ) -> Result<(), RepoError>;

    /// Quita al miembro y revoca sus `secret_envelopes` para exactamente los
    /// recursos que el grupo comparte — sin re-cifrar nada de nadie más.
    async fn quitar(&self, group_id: Uuid, user_id: Uuid, resource_ids_a_revocar: &[Uuid]) -> Result<(), RepoError>;

    async fn es_miembro(&self, group_id: Uuid, user_id: Uuid) -> Result<bool, RepoError>;

    async fn miembro(&self, group_id: Uuid, user_id: Uuid) -> Result<Option<Miembro>, RepoError>;

    async fn es_manager_de_alguno(&self, user_id: Uuid, group_ids: &[Uuid]) -> Result<bool, RepoError>;

    async fn contar_managers(&self, group_id: Uuid) -> Result<i64, RepoError>;

    async fn contar_miembros(&self, group_id: Uuid) -> Result<i64, RepoError>;

    async fn set_admin(&self, group_id: Uuid, user_id: Uuid, is_admin: bool) -> Result<(), RepoError>;

    async fn miembros_de(&self, group_id: Uuid) -> Result<Vec<Miembro>, RepoError>;

    /// `GET /me/groups` — todos los grupos a los que pertenece `user_id`,
    /// con `is_admin` por grupo.
    async fn grupos_de(&self, user_id: Uuid) -> Result<Vec<GrupoDeUsuario>, RepoError>;

    /// 2026-08-11: `true` si `user_id` es admin (`is_admin`) de al menos un
    /// grupo — usado para elegibilidad de anidar/compartir carpetas y
    /// visibilidad ampliada de usuarios (F-11).
    async fn es_admin_de_algun_grupo(&self, user_id: Uuid) -> Result<bool, RepoError>;

    /// `group_id` de cada grupo donde `user_id` es admin — usado para el
    /// selector "compartir con mi grupo" y para autorizar `DELETE
    /// /resources/{id}` de un recurso que vive en una carpeta de grupo.
    async fn grupos_administrados_por(&self, user_id: Uuid) -> Result<Vec<Uuid>, RepoError>;

    /// F-19: grupos raíz **gestionados por Directory Sync**
    /// (`managed_by_directory_sync`) a los que pertenece `user_id` — usado
    /// sólo para la reconciliación de salida (alguien ya no aparece en el
    /// `memberOf` actual). Nunca incluye un grupo armado a mano, aunque el
    /// usuario también sea miembro de uno con el mismo nombre.
    async fn grupos_gestionados_de(&self, user_id: Uuid) -> Result<Vec<GrupoDeUsuario>, RepoError>;
}

pub trait OrganizationRepository {
    async fn max_group_depth(&self) -> Result<i32, RepoError>;
}

#[derive(Clone)]
pub struct PgGroupRepository {
    pub pool: sqlx::PgPool,
}

impl GroupRepository for PgGroupRepository {
    async fn crear(&self, id: Uuid, name: &str, parent_group_id: Option<Uuid>) -> Result<Group, RepoError> {
        let fila = sqlx::query!(
            r#"
            insert into groups (id, name, parent_group_id)
            values ($1, $2, $3)
            returning id, name, parent_group_id, share_exempt
            "#,
            id,
            name,
            parent_group_id,
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => RepoError::Conflict,
            _ => RepoError::Database(e),
        })?;

        Ok(Group { id: fila.id, name: fila.name, parent_group_id: fila.parent_group_id, share_exempt: fila.share_exempt })
    }

    async fn buscar(&self, id: Uuid) -> Result<Option<Group>, RepoError> {
        let fila = sqlx::query!(
            r#"select id, name, parent_group_id, share_exempt from groups where id = $1 and deleted_at is null"#,
            id,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(fila.map(|f| Group { id: f.id, name: f.name, parent_group_id: f.parent_group_id, share_exempt: f.share_exempt }))
    }

    async fn hijos_directos(&self, group_id: Uuid) -> Result<Vec<Group>, RepoError> {
        let filas = sqlx::query!(
            r#"
            select id, name, parent_group_id, share_exempt from groups
            where parent_group_id = $1 and deleted_at is null
            order by name
            "#,
            group_id,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(filas
            .into_iter()
            .map(|f| Group { id: f.id, name: f.name, parent_group_id: f.parent_group_id, share_exempt: f.share_exempt })
            .collect())
    }

    async fn raices(&self) -> Result<Vec<Group>, RepoError> {
        let filas = sqlx::query!(
            r#"
            select id, name, parent_group_id, share_exempt from groups
            where parent_group_id is null and deleted_at is null
            order by name
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(filas
            .into_iter()
            .map(|f| Group { id: f.id, name: f.name, parent_group_id: f.parent_group_id, share_exempt: f.share_exempt })
            .collect())
    }

    async fn tiene_hijos(&self, group_id: Uuid) -> Result<bool, RepoError> {
        let fila = sqlx::query!(
            r#"select 1 as "existe!" from groups where parent_group_id = $1 and deleted_at is null limit 1"#,
            group_id,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(fila.is_some())
    }

    async fn ancestros_inclusive(&self, group_id: Uuid) -> Result<Vec<Uuid>, RepoError> {
        let filas = sqlx::query!(
            r#"
            with recursive ancestros as (
                select id, parent_group_id from groups where id = $1
                union all
                select g.id, g.parent_group_id
                from groups g
                join ancestros a on g.id = a.parent_group_id
            )
            select id as "id!" from ancestros
            "#,
            group_id,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(filas.into_iter().map(|f| f.id).collect())
    }

    async fn profundidad(&self, group_id: Uuid) -> Result<i32, RepoError> {
        Ok(self.ancestros_inclusive(group_id).await?.len() as i32)
    }

    async fn mover(&self, group_id: Uuid, new_parent_group_id: Option<Uuid>) -> Result<(), RepoError> {
        sqlx::query!(
            r#"update groups set parent_group_id = $2 where id = $1"#,
            group_id,
            new_parent_group_id,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn eliminar(&self, group_id: Uuid) -> Result<(), RepoError> {
        sqlx::query!(r#"update groups set deleted_at = now() where id = $1"#, group_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn actualizar_share_exempt(&self, group_id: Uuid, exempt: bool) -> Result<(), RepoError> {
        sqlx::query!(r#"update groups set share_exempt = $2 where id = $1"#, group_id, exempt)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn buscar_o_crear_raiz_gestionado(&self, name: &str) -> Result<Uuid, RepoError> {
        let fila = sqlx::query!(
            r#"
            insert into groups (name, managed_by_directory_sync)
            values ($1, true)
            on conflict (name) where parent_group_id is null and deleted_at is null
                do update set name = excluded.name
            returning id
            "#,
            name,
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(fila.id)
    }
}

#[derive(Clone)]
pub struct PgGroupMemberRepository {
    pub pool: sqlx::PgPool,
}

impl GroupMemberRepository for PgGroupMemberRepository {
    async fn agregar_simple(&self, group_id: Uuid, user_id: Uuid, is_admin: bool) -> Result<(), RepoError> {
        sqlx::query!(
            r#"insert into group_members (group_id, user_id, is_admin) values ($1, $2, $3)"#,
            group_id,
            user_id,
            is_admin,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => RepoError::Conflict,
            _ => RepoError::Database(e),
        })?;
        Ok(())
    }

    async fn agregar_con_envelopes(
        &self,
        group_id: Uuid,
        user_id: Uuid,
        is_admin: bool,
        envelopes: &[EnvelopeParaMiembroNuevo],
    ) -> Result<(), RepoError> {
        let mut tx = self.pool.begin().await?;

        sqlx::query!(
            r#"insert into group_members (group_id, user_id, is_admin) values ($1, $2, $3)"#,
            group_id,
            user_id,
            is_admin,
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => RepoError::Conflict,
            _ => RepoError::Database(e),
        })?;

        for envelope in envelopes {
            sqlx::query!(
                r#"
                insert into secret_envelopes (resource_id, user_id, sealed_dek, secret_ciphertext, secret_nonce)
                values ($1, $2, $3, $4, $5)
                on conflict (resource_id, user_id) do nothing
                "#,
                envelope.resource_id,
                user_id,
                envelope.sealed_dek,
                envelope.secret_ciphertext,
                envelope.secret_nonce,
            )
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    async fn quitar(&self, group_id: Uuid, user_id: Uuid, resource_ids_a_revocar: &[Uuid]) -> Result<(), RepoError> {
        let mut tx = self.pool.begin().await?;

        sqlx::query!(
            r#"delete from group_members where group_id = $1 and user_id = $2"#,
            group_id,
            user_id,
        )
        .execute(&mut *tx)
        .await?;

        if !resource_ids_a_revocar.is_empty() {
            sqlx::query!(
                r#"delete from secret_envelopes where user_id = $1 and resource_id = any($2)"#,
                user_id,
                resource_ids_a_revocar,
            )
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    async fn es_miembro(&self, group_id: Uuid, user_id: Uuid) -> Result<bool, RepoError> {
        let fila = sqlx::query!(
            r#"select 1 as "existe!" from group_members where group_id = $1 and user_id = $2"#,
            group_id,
            user_id,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(fila.is_some())
    }

    async fn miembro(&self, group_id: Uuid, user_id: Uuid) -> Result<Option<Miembro>, RepoError> {
        let fila = sqlx::query!(
            r#"select gm.user_id, gm.is_admin, u.email, u.display_name
               from group_members gm join users u on u.id = gm.user_id
               where gm.group_id = $1 and gm.user_id = $2"#,
            group_id,
            user_id,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(fila.map(|f| Miembro { user_id: f.user_id, is_admin: f.is_admin, email: f.email, display_name: f.display_name }))
    }

    async fn es_manager_de_alguno(&self, user_id: Uuid, group_ids: &[Uuid]) -> Result<bool, RepoError> {
        let fila = sqlx::query!(
            r#"
            select 1 as "existe!" from group_members
            where user_id = $1 and is_admin and group_id = any($2)
            limit 1
            "#,
            user_id,
            group_ids,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(fila.is_some())
    }

    async fn contar_managers(&self, group_id: Uuid) -> Result<i64, RepoError> {
        let fila = sqlx::query!(
            r#"select count(*) as "n!" from group_members where group_id = $1 and is_admin"#,
            group_id,
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(fila.n)
    }

    async fn contar_miembros(&self, group_id: Uuid) -> Result<i64, RepoError> {
        let fila = sqlx::query!(
            r#"select count(*) as "n!" from group_members where group_id = $1"#,
            group_id,
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(fila.n)
    }

    async fn set_admin(&self, group_id: Uuid, user_id: Uuid, is_admin: bool) -> Result<(), RepoError> {
        sqlx::query!(
            r#"update group_members set is_admin = $3 where group_id = $1 and user_id = $2"#,
            group_id,
            user_id,
            is_admin,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn miembros_de(&self, group_id: Uuid) -> Result<Vec<Miembro>, RepoError> {
        let filas = sqlx::query!(
            r#"select gm.user_id, gm.is_admin, u.email, u.display_name
               from group_members gm join users u on u.id = gm.user_id
               where gm.group_id = $1 order by gm.created_at"#,
            group_id,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(filas
            .into_iter()
            .map(|f| Miembro { user_id: f.user_id, is_admin: f.is_admin, email: f.email, display_name: f.display_name })
            .collect())
    }

    async fn grupos_de(&self, user_id: Uuid) -> Result<Vec<GrupoDeUsuario>, RepoError> {
        let filas = sqlx::query!(
            r#"select g.id as group_id, g.name, gm.is_admin
               from group_members gm join groups g on g.id = gm.group_id and g.deleted_at is null
               where gm.user_id = $1 order by g.name"#,
            user_id,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(filas.into_iter().map(|f| GrupoDeUsuario { group_id: f.group_id, name: f.name, is_admin: f.is_admin }).collect())
    }

    async fn es_admin_de_algun_grupo(&self, user_id: Uuid) -> Result<bool, RepoError> {
        let fila = sqlx::query!(
            r#"select 1 as "existe!" from group_members where user_id = $1 and is_admin limit 1"#,
            user_id,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(fila.is_some())
    }

    async fn grupos_administrados_por(&self, user_id: Uuid) -> Result<Vec<Uuid>, RepoError> {
        let filas = sqlx::query!(
            r#"select group_id from group_members where user_id = $1 and is_admin"#,
            user_id,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(filas.into_iter().map(|f| f.group_id).collect())
    }

    async fn grupos_gestionados_de(&self, user_id: Uuid) -> Result<Vec<GrupoDeUsuario>, RepoError> {
        let filas = sqlx::query!(
            r#"
            select g.id as group_id, g.name, gm.is_admin
            from group_members gm
            join groups g on g.id = gm.group_id and g.deleted_at is null
            where gm.user_id = $1 and g.parent_group_id is null and g.managed_by_directory_sync
            order by g.name
            "#,
            user_id,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(filas.into_iter().map(|f| GrupoDeUsuario { group_id: f.group_id, name: f.name, is_admin: f.is_admin }).collect())
    }
}

#[derive(Clone)]
pub struct PgOrganizationRepository {
    pub pool: sqlx::PgPool,
}

impl OrganizationRepository for PgOrganizationRepository {
    async fn max_group_depth(&self) -> Result<i32, RepoError> {
        let fila = sqlx::query!(r#"select max_group_depth from organizations where id = 1"#)
            .fetch_one(&self.pool)
            .await?;
        Ok(fila.max_group_depth)
    }
}
