// Autor: Athan Espinoza

//! `async fn` en estos traits es intencional: se usan sólo dentro de este
//! crate (genéricos, no `dyn`), así que la falta de bounds explícitos de
//! `Send` en la firma del trait no es un problema real.
#![allow(async_fn_in_trait)]

use uuid::Uuid;

use crate::error::RepoError;

use super::models::{Destinatario, EnvelopeInput, Resource, SecretEnvelope};

pub trait ResourceRepository {
    #[allow(clippy::too_many_arguments)]
    async fn crear(
        &self,
        id: Uuid,
        resource_type_id: Uuid,
        metadata_ciphertext: &[u8],
        metadata_nonce: &[u8],
        created_by: Uuid,
        metadata_key_id: Option<Uuid>,
    ) -> Result<Resource, RepoError>;

    async fn buscar(&self, id: Uuid) -> Result<Option<Resource>, RepoError>;

    /// Recursos donde `user_id` tiene al menos permiso `read` — join contra
    /// `permissions` (sin grupos todavía, F-11 básico).
    async fn listar_visibles_por(&self, user_id: Uuid) -> Result<Vec<Resource>, RepoError>;

    /// F-33: re-envuelve la metadata de un recurso hacia otra metadata key
    /// (ej. la entrante de una rotación en curso) — `UPDATE` condicionado a
    /// que la fila siga apuntando a `expected_current_metadata_key_id`, para
    /// no pisar una migración/edición concurrente de la misma fila. Devuelve
    /// `false` si la condición no matcheó (ya migrado, o recurso inexistente).
    #[allow(clippy::too_many_arguments)]
    async fn rekey_metadata(
        &self,
        resource_id: Uuid,
        expected_current_metadata_key_id: Uuid,
        new_metadata_key_id: Uuid,
        metadata_ciphertext: &[u8],
        metadata_nonce: &[u8],
    ) -> Result<bool, RepoError>;

    /// F-07: editar un recurso ya creado. Concurrencia optimista real —
    /// `expected_updated_at` viene del `If-Match` del cliente (último `GET`
    /// que hizo); si no coincide con el `updated_at` actual, no aplica nada
    /// y devuelve `Ok(None)` (el handler lo traduce a `409`). Reemplaza
    /// metadata **y** todas las filas de `secret_envelopes` del recurso en
    /// una única transacción — el cliente ya las re-selló client-side para
    /// cada destinatario actual (`listar_destinatarios`), el servidor nunca
    /// re-cifra nada.
    #[allow(clippy::too_many_arguments)]
    async fn actualizar(
        &self,
        resource_id: Uuid,
        expected_updated_at: time::OffsetDateTime,
        metadata_ciphertext: &[u8],
        metadata_nonce: &[u8],
        envelopes: &[EnvelopeInput],
    ) -> Result<Option<Resource>, RepoError>;

    /// F-07: quiénes tienen hoy un `secret_envelope` propio en este recurso
    /// — lo que el cliente necesita para re-sellar la DEK nueva al editar,
    /// mismo dato que ya resuelve `compartir` para un destinatario nuevo.
    async fn listar_destinatarios(&self, resource_id: Uuid) -> Result<Vec<Destinatario>, RepoError>;
}

pub trait ResourceTypeRepository {
    async fn id_por_slug(&self, slug: &str) -> Result<Option<Uuid>, RepoError>;

    /// F-08: el `json_schema` completo — el servidor sólo lo usa para
    /// derivar si el tipo declara `totp_secret` en `secret`
    /// (`GET /resources/{id}/totp`), nunca para interpretar contenido
    /// cifrado.
    async fn json_schema_por_id(&self, id: Uuid) -> Result<Option<serde_json::Value>, RepoError>;
}

pub trait SecretEnvelopeRepository {
    #[allow(clippy::too_many_arguments)]
    async fn insertar(
        &self,
        resource_id: Uuid,
        user_id: Uuid,
        sealed_dek: &[u8],
        secret_ciphertext: &[u8],
        secret_nonce: &[u8],
    ) -> Result<(), RepoError>;

    async fn buscar(
        &self,
        resource_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<SecretEnvelope>, RepoError>;
}

pub trait PermissionRepository {
    /// `subject_type` ∈ {`resource`, `folder`} — mismo `permissions.subject_type`
    /// que ya soporta el schema desde Fase 1.1, generalizado acá (Carpetas,
    /// F-09/F-11) para no duplicar esta lógica una segunda vez.
    async fn otorgar(
        &self,
        subject_type: &str,
        subject_id: Uuid,
        user_id: Uuid,
        nivel: &str,
    ) -> Result<(), RepoError>;

    /// `true` si `user_id` tiene exactamente `nivel` o uno más alto
    /// (`owner` > `update` > `read`) sobre `subject_type`/`subject_id` —
    /// directo (`grantee_type = 'user'`) o vía membresía de un grupo con
    /// acceso (F-12: `grantee_type = 'group'`, resuelto contra `group_members`).
    async fn tiene_permiso(
        &self,
        subject_type: &str,
        subject_id: Uuid,
        user_id: Uuid,
        nivel_minimo: &str,
    ) -> Result<bool, RepoError>;

    /// `subject_id` de tipo `resource` donde `grantee_type`/`grantee_id`
    /// tiene acceso — F-12 lo usa para saber qué recursos ya comparte un
    /// grupo antes de agregar un miembro nuevo.
    async fn recursos_por_grantee(&self, grantee_type: &str, grantee_id: Uuid) -> Result<Vec<Uuid>, RepoError>;

    /// `true` si, además de `grantee_type`/`grantee_id`, existe **otro**
    /// grantee con nivel `owner` sobre el mismo `subject` — F-12 lo usa para
    /// rechazar borrar un grupo que sea único Owner de algo.
    #[allow(clippy::too_many_arguments)]
    async fn existe_otro_owner(
        &self,
        subject_type: &str,
        subject_id: Uuid,
        excluir_grantee_type: &str,
        excluir_grantee_id: Uuid,
    ) -> Result<bool, RepoError>;

    /// `(subject_type, subject_id)` donde `grantee_type`/`grantee_id` tiene
    /// exactamente nivel `owner` — F-12 recorre esto al intentar borrar un
    /// grupo.
    async fn subjects_owner_de(
        &self,
        grantee_type: &str,
        grantee_id: Uuid,
    ) -> Result<Vec<(String, Uuid)>, RepoError>;

    /// `true` si `subject_type`/`subject_id` tiene AL MENOS una fila en
    /// `permissions` (de cualquier grantee) — F-11 lo usa para distinguir
    /// una carpeta ya compartida (exige `update` mínimo para operar) de una
    /// todavía sin compartir (personal, sin restricción — mismo bypass que
    /// Passbolt hace para carpetas 100% personales, y necesario además para
    /// no bloquear carpetas creadas antes de que F-11 existiera, que nunca
    /// tuvieron ninguna fila de permiso).
    async fn existe_algun_permiso(&self, subject_type: &str, subject_id: Uuid) -> Result<bool, RepoError>;
}

#[derive(Clone)]
pub struct PgResourceRepository {
    pub pool: sqlx::PgPool,
}

impl ResourceRepository for PgResourceRepository {
    async fn crear(
        &self,
        id: Uuid,
        resource_type_id: Uuid,
        metadata_ciphertext: &[u8],
        metadata_nonce: &[u8],
        created_by: Uuid,
        metadata_key_id: Option<Uuid>,
    ) -> Result<Resource, RepoError> {
        let metadata_key_type = if metadata_key_id.is_some() { "shared_key" } else { "user_key" };
        let fila = sqlx::query!(
            r#"
            insert into resources (
                id, resource_type_id, metadata_ciphertext, metadata_nonce, created_by,
                metadata_key_id, metadata_key_type
            )
            values ($1, $2, $3, $4, $5, $6, $7)
            returning id, resource_type_id, metadata_ciphertext, metadata_nonce, created_by, created_at,
                      updated_at, metadata_key_type, metadata_key_id
            "#,
            id,
            resource_type_id,
            metadata_ciphertext,
            metadata_nonce,
            created_by,
            metadata_key_id,
            metadata_key_type,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(Resource {
            id: fila.id,
            resource_type_id: fila.resource_type_id,
            metadata_ciphertext: fila.metadata_ciphertext,
            metadata_nonce: fila.metadata_nonce,
            created_by: fila.created_by,
            created_at: fila.created_at,
            updated_at: fila.updated_at,
            metadata_key_type: fila.metadata_key_type,
            metadata_key_id: fila.metadata_key_id,
        })
    }

    async fn buscar(&self, id: Uuid) -> Result<Option<Resource>, RepoError> {
        let fila = sqlx::query!(
            r#"
            select id, resource_type_id, metadata_ciphertext, metadata_nonce, created_by, created_at,
                   updated_at, metadata_key_type, metadata_key_id
            from resources where id = $1 and deleted_at is null
            "#,
            id,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(fila.map(|f| Resource {
            id: f.id,
            resource_type_id: f.resource_type_id,
            metadata_ciphertext: f.metadata_ciphertext,
            metadata_nonce: f.metadata_nonce,
            created_by: f.created_by,
            created_at: f.created_at,
            updated_at: f.updated_at,
            metadata_key_type: f.metadata_key_type,
            metadata_key_id: f.metadata_key_id,
        }))
    }

    async fn listar_visibles_por(&self, user_id: Uuid) -> Result<Vec<Resource>, RepoError> {
        let filas = sqlx::query!(
            r#"
            select distinct r.id, r.resource_type_id, r.metadata_ciphertext, r.metadata_nonce,
                   r.created_by, r.created_at, r.updated_at, r.metadata_key_type, r.metadata_key_id
            from resources r
            join permissions p on p.subject_type = 'resource' and p.subject_id = r.id
            where p.grantee_type = 'user' and p.grantee_id = $1 and r.deleted_at is null
            order by r.created_at desc
            "#,
            user_id,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(filas
            .into_iter()
            .map(|f| Resource {
                id: f.id,
                resource_type_id: f.resource_type_id,
                metadata_ciphertext: f.metadata_ciphertext,
                metadata_nonce: f.metadata_nonce,
                created_by: f.created_by,
                created_at: f.created_at,
                updated_at: f.updated_at,
                metadata_key_type: f.metadata_key_type,
                metadata_key_id: f.metadata_key_id,
            })
            .collect())
    }

    async fn rekey_metadata(
        &self,
        resource_id: Uuid,
        expected_current_metadata_key_id: Uuid,
        new_metadata_key_id: Uuid,
        metadata_ciphertext: &[u8],
        metadata_nonce: &[u8],
    ) -> Result<bool, RepoError> {
        let resultado = sqlx::query!(
            r#"
            update resources
            set metadata_ciphertext = $1, metadata_nonce = $2, metadata_key_id = $3
            where id = $4 and metadata_key_id = $5 and deleted_at is null
            "#,
            metadata_ciphertext,
            metadata_nonce,
            new_metadata_key_id,
            resource_id,
            expected_current_metadata_key_id,
        )
        .execute(&self.pool)
        .await?;
        Ok(resultado.rows_affected() == 1)
    }

    async fn actualizar(
        &self,
        resource_id: Uuid,
        expected_updated_at: time::OffsetDateTime,
        metadata_ciphertext: &[u8],
        metadata_nonce: &[u8],
        envelopes: &[EnvelopeInput],
    ) -> Result<Option<Resource>, RepoError> {
        let mut tx = self.pool.begin().await?;

        // Concurrencia optimista: el `UPDATE` sólo aplica si `updated_at`
        // sigue siendo el que el cliente vio en su último `GET` — una
        // edición concurrente (dos pestañas, o edición web + import) ya
        // habría corrido su propio `UPDATE` y adelantado `updated_at`,
        // haciendo que éste no afecte ninguna fila.
        let fila = sqlx::query!(
            r#"
            update resources
            set metadata_ciphertext = $1, metadata_nonce = $2, updated_at = now()
            where id = $3 and updated_at = $4 and deleted_at is null
            returning id, resource_type_id, metadata_ciphertext, metadata_nonce, created_by, created_at,
                      updated_at, metadata_key_type, metadata_key_id
            "#,
            metadata_ciphertext,
            metadata_nonce,
            resource_id,
            expected_updated_at,
        )
        .fetch_optional(&mut *tx)
        .await?;

        let Some(fila) = fila else {
            return Ok(None);
        };

        // Reemplazo completo de `secret_envelopes`: el cliente ya resolvió
        // la lista completa de destinatarios actuales (`listar_destinatarios`)
        // y las re-selló con la DEK nueva — nunca un merge parcial, porque
        // un destinatario que se hubiera agregado/quitado entre el `GET` de
        // destinatarios y este `PUT` quedaría con un envelope inconsistente.
        sqlx::query!(r#"delete from secret_envelopes where resource_id = $1"#, resource_id)
            .execute(&mut *tx)
            .await?;

        for env in envelopes {
            sqlx::query!(
                r#"
                insert into secret_envelopes (resource_id, user_id, sealed_dek, secret_ciphertext, secret_nonce)
                values ($1, $2, $3, $4, $5)
                "#,
                resource_id,
                env.user_id,
                env.sealed_dek,
                env.secret_ciphertext,
                env.secret_nonce,
            )
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        Ok(Some(Resource {
            id: fila.id,
            resource_type_id: fila.resource_type_id,
            metadata_ciphertext: fila.metadata_ciphertext,
            metadata_nonce: fila.metadata_nonce,
            created_by: fila.created_by,
            created_at: fila.created_at,
            updated_at: fila.updated_at,
            metadata_key_type: fila.metadata_key_type,
            metadata_key_id: fila.metadata_key_id,
        }))
    }

    async fn listar_destinatarios(&self, resource_id: Uuid) -> Result<Vec<Destinatario>, RepoError> {
        let filas = sqlx::query!(
            r#"
            select se.user_id, uk.public_key_x25519
            from secret_envelopes se
            join user_keys uk on uk.user_id = se.user_id
            where se.resource_id = $1
            "#,
            resource_id,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(filas.into_iter().map(|f| Destinatario { user_id: f.user_id, public_key_x25519: f.public_key_x25519 }).collect())
    }
}

#[derive(Clone)]
pub struct PgResourceTypeRepository {
    pub pool: sqlx::PgPool,
}

impl ResourceTypeRepository for PgResourceTypeRepository {
    async fn id_por_slug(&self, slug: &str) -> Result<Option<Uuid>, RepoError> {
        let fila = sqlx::query!(
            r#"select id from resource_types where slug = $1 and deleted_at is null"#,
            slug,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(fila.map(|f| f.id))
    }

    async fn json_schema_por_id(&self, id: Uuid) -> Result<Option<serde_json::Value>, RepoError> {
        let fila = sqlx::query!(
            r#"select json_schema from resource_types where id = $1 and deleted_at is null"#,
            id,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(fila.map(|f| f.json_schema))
    }
}

#[derive(Clone)]
pub struct PgSecretEnvelopeRepository {
    pub pool: sqlx::PgPool,
}

impl SecretEnvelopeRepository for PgSecretEnvelopeRepository {
    async fn insertar(
        &self,
        resource_id: Uuid,
        user_id: Uuid,
        sealed_dek: &[u8],
        secret_ciphertext: &[u8],
        secret_nonce: &[u8],
    ) -> Result<(), RepoError> {
        sqlx::query!(
            r#"
            insert into secret_envelopes (resource_id, user_id, sealed_dek, secret_ciphertext, secret_nonce)
            values ($1, $2, $3, $4, $5)
            "#,
            resource_id,
            user_id,
            sealed_dek,
            secret_ciphertext,
            secret_nonce,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db) if db.is_unique_violation() => RepoError::Conflict,
            _ => RepoError::Database(e),
        })?;
        Ok(())
    }

    async fn buscar(
        &self,
        resource_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<SecretEnvelope>, RepoError> {
        let fila = sqlx::query!(
            r#"
            select sealed_dek, secret_ciphertext, secret_nonce
            from secret_envelopes where resource_id = $1 and user_id = $2
            "#,
            resource_id,
            user_id,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(fila.map(|f| SecretEnvelope {
            sealed_dek: f.sealed_dek,
            secret_ciphertext: f.secret_ciphertext,
            secret_nonce: f.secret_nonce,
        }))
    }
}

#[derive(Clone)]
pub struct PgPermissionRepository {
    pub pool: sqlx::PgPool,
}

impl PermissionRepository for PgPermissionRepository {
    async fn otorgar(&self, subject_type: &str, subject_id: Uuid, user_id: Uuid, nivel: &str) -> Result<(), RepoError> {
        sqlx::query!(
            r#"
            insert into permissions (subject_type, subject_id, grantee_type, grantee_id, level)
            values ($1, $2, 'user', $3, $4)
            on conflict (subject_type, subject_id, grantee_type, grantee_id)
            do update set level = excluded.level
            "#,
            subject_type,
            subject_id,
            user_id,
            nivel,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn tiene_permiso(
        &self,
        subject_type: &str,
        subject_id: Uuid,
        user_id: Uuid,
        nivel_minimo: &str,
    ) -> Result<bool, RepoError> {
        let filas = sqlx::query!(
            r#"
            select level from permissions
            where subject_type = $1 and subject_id = $2
              and (
                (grantee_type = 'user' and grantee_id = $3)
                or (grantee_type = 'group' and grantee_id in (
                    select group_id from group_members where user_id = $3
                ))
              )
            "#,
            subject_type,
            subject_id,
            user_id,
        )
        .fetch_all(&self.pool)
        .await?;

        let orden = |n: &str| match n {
            "read" => 0,
            "update" => 1,
            "owner" => 2,
            _ => -1,
        };

        Ok(filas.iter().any(|f| orden(&f.level) >= orden(nivel_minimo)))
    }

    async fn recursos_por_grantee(&self, grantee_type: &str, grantee_id: Uuid) -> Result<Vec<Uuid>, RepoError> {
        let filas = sqlx::query!(
            r#"
            select subject_id from permissions
            where subject_type = 'resource' and grantee_type = $1 and grantee_id = $2
            "#,
            grantee_type,
            grantee_id,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(filas.into_iter().map(|f| f.subject_id).collect())
    }

    async fn existe_otro_owner(
        &self,
        subject_type: &str,
        subject_id: Uuid,
        excluir_grantee_type: &str,
        excluir_grantee_id: Uuid,
    ) -> Result<bool, RepoError> {
        let fila = sqlx::query!(
            r#"
            select 1 as "existe!" from permissions
            where subject_type = $1 and subject_id = $2 and level = 'owner'
              and not (grantee_type = $3 and grantee_id = $4)
            limit 1
            "#,
            subject_type,
            subject_id,
            excluir_grantee_type,
            excluir_grantee_id,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(fila.is_some())
    }

    async fn subjects_owner_de(
        &self,
        grantee_type: &str,
        grantee_id: Uuid,
    ) -> Result<Vec<(String, Uuid)>, RepoError> {
        let filas = sqlx::query!(
            r#"
            select subject_type, subject_id from permissions
            where grantee_type = $1 and grantee_id = $2 and level = 'owner'
            "#,
            grantee_type,
            grantee_id,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(filas.into_iter().map(|f| (f.subject_type, f.subject_id)).collect())
    }

    async fn existe_algun_permiso(&self, subject_type: &str, subject_id: Uuid) -> Result<bool, RepoError> {
        let fila = sqlx::query!(
            r#"select 1 as "existe!" from permissions where subject_type = $1 and subject_id = $2 limit 1"#,
            subject_type,
            subject_id,
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(fila.is_some())
    }
}
