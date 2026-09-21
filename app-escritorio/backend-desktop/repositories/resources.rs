// Autor: Athan Espinoza

//! Segunda implementación (SQLite, modo escritorio) de los repositorios de
//! `resources`. `PermissionRepository` es la más recortada: sin tabla
//! `permissions` (no se porta, spec/13 §5) — "tiene permiso" colapsa a "es
//! el dueño" (`resources.created_by == user_id`), sin niveles read/update/
//! owner (en 1 usuario no hay distinción real que hacer) y sin ningún
//! concepto de grupo. `otorgar`/`revocar` son no-ops: la propiedad ya está
//! implícita en `created_by`, no hace falta una fila aparte que la duplique.

use sqlx::{Row, SqlitePool};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::desktop::sqlite_util::{fmt_dt, parse_dt, parse_uuid};
use crate::error::RepoError;

use crate::resources::models::{Destinatario, EnvelopeInput, PermisoGrantee, Resource, SecretEnvelope};
use crate::resources::repository::{PermissionRepository, ResourceRepository, ResourceTypeRepository, SecretEnvelopeRepository};

pub fn fila_a_resource(row: &sqlx::sqlite::SqliteRow) -> Result<Resource, RepoError> {
    Ok(Resource {
        id: parse_uuid(row.try_get::<String, _>("id")?.as_str())?,
        resource_type_id: parse_uuid(row.try_get::<String, _>("resource_type_id")?.as_str())?,
        metadata_ciphertext: row.try_get("metadata_ciphertext")?,
        metadata_nonce: row.try_get("metadata_nonce")?,
        created_by: Some(parse_uuid(row.try_get::<String, _>("created_by")?.as_str())?),
        created_at: parse_dt(row.try_get::<String, _>("created_at")?.as_str())?,
        updated_at: parse_dt(row.try_get::<String, _>("updated_at")?.as_str())?,
        metadata_key_type: row.try_get("metadata_key_type")?,
        metadata_key_id: row.try_get::<Option<String>, _>("metadata_key_id")?.map(|s| parse_uuid(&s)).transpose()?,
    })
}

/// Nueva versión (`updated_at`) de un recurso que se está editando. El
/// `updated_at` hace de versión para la concurrencia optimista (`If-Match`),
/// y con precisión de milisegundos dos ediciones dentro del mismo milisegundo
/// darían la MISMA versión: la segunda vería su `If-Match` todavía vigente y
/// pisaría a la primera sin conflicto. Por eso la versión nueva es siempre
/// estrictamente posterior a la que se reemplaza.
fn nueva_version(anterior: OffsetDateTime) -> OffsetDateTime {
    OffsetDateTime::now_utc().max(anterior + time::Duration::milliseconds(1))
}

#[derive(Clone)]
pub struct SqliteResourceRepository {
    pub pool: SqlitePool,
}

impl ResourceRepository for SqliteResourceRepository {
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
        let ahora = fmt_dt(OffsetDateTime::now_utc());
        sqlx::query(
            "insert into resources (id, resource_type_id, metadata_ciphertext, metadata_nonce, created_by, \
             metadata_key_id, metadata_key_type, created_at, updated_at) values (?1,?2,?3,?4,?5,?6,?7,?8,?8)",
        )
        .bind(id.to_string())
        .bind(resource_type_id.to_string())
        .bind(metadata_ciphertext)
        .bind(metadata_nonce)
        .bind(created_by.to_string())
        .bind(metadata_key_id.map(|u| u.to_string()))
        .bind(metadata_key_type)
        .bind(&ahora)
        .execute(&self.pool)
        .await?;

        Ok(Resource {
            id,
            resource_type_id,
            metadata_ciphertext: metadata_ciphertext.to_vec(),
            metadata_nonce: metadata_nonce.to_vec(),
            created_by: Some(created_by),
            created_at: parse_dt(&ahora)?,
            updated_at: parse_dt(&ahora)?,
            metadata_key_type: metadata_key_type.to_string(),
            metadata_key_id,
        })
    }

    async fn buscar(&self, id: Uuid) -> Result<Option<Resource>, RepoError> {
        let fila = sqlx::query(
            "select id, resource_type_id, metadata_ciphertext, metadata_nonce, created_by, created_at, \
             updated_at, metadata_key_type, metadata_key_id from resources where id = ?1 and deleted_at is null",
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        fila.as_ref().map(fila_a_resource).transpose()
    }

    async fn marcar_eliminado(&self, id: Uuid) -> Result<bool, RepoError> {
        let resultado = sqlx::query("update resources set deleted_at = ?2 where id = ?1 and deleted_at is null")
            .bind(id.to_string())
            .bind(fmt_dt(OffsetDateTime::now_utc()))
            .execute(&self.pool)
            .await?;
        Ok(resultado.rows_affected() > 0)
    }

    async fn cambiar_tipo(&self, id: Uuid, nuevo_resource_type_id: Uuid) -> Result<bool, RepoError> {
        let resultado = sqlx::query(
            "update resources set resource_type_id = ?2, updated_at = ?3 where id = ?1 and deleted_at is null",
        )
        .bind(id.to_string())
        .bind(nuevo_resource_type_id.to_string())
        .bind(fmt_dt(OffsetDateTime::now_utc()))
        .execute(&self.pool)
        .await?;
        Ok(resultado.rows_affected() > 0)
    }

    /// Sin `permissions` en este modo (spec/13 §5) — "visible por" colapsa a
    /// "creado por" (1 usuario, todo lo que existe es suyo).
    async fn listar_visibles_por(&self, user_id: Uuid) -> Result<Vec<Resource>, RepoError> {
        let filas = sqlx::query(
            "select id, resource_type_id, metadata_ciphertext, metadata_nonce, created_by, created_at, \
             updated_at, metadata_key_type, metadata_key_id from resources \
             where created_by = ?1 and deleted_at is null order by created_at desc",
        )
        .bind(user_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        filas.iter().map(fila_a_resource).collect()
    }

    /// F-47 (sync): sin consumidor en este modo todavía — el backend local
    /// nunca SIRVE `/sync` (eso lo hace el servidor remoto al que este modo
    /// se conecta, spec/13 §7), pero el trait es compartido, así que hace
    /// falta una implementación real igual.
    async fn cambios_desde(&self, user_id: Uuid, desde: OffsetDateTime) -> Result<Vec<Resource>, RepoError> {
        let filas = sqlx::query(
            "select id, resource_type_id, metadata_ciphertext, metadata_nonce, created_by, created_at, \
             updated_at, metadata_key_type, metadata_key_id from resources \
             where created_by = ?1 and deleted_at is null and updated_at > ?2 order by created_at desc",
        )
        .bind(user_id.to_string())
        .bind(fmt_dt(desde))
        .fetch_all(&self.pool)
        .await?;
        filas.iter().map(fila_a_resource).collect()
    }

    async fn ids_eliminados_desde(&self, user_id: Uuid, desde: OffsetDateTime) -> Result<Vec<Uuid>, RepoError> {
        let filas = sqlx::query("select id from resources where created_by = ?1 and deleted_at is not null and deleted_at > ?2")
            .bind(user_id.to_string())
            .bind(fmt_dt(desde))
            .fetch_all(&self.pool)
            .await?;
        filas.iter().map(|f| parse_uuid(f.try_get::<String, _>("id")?.as_str())).collect()
    }

    async fn rekey_metadata(
        &self,
        resource_id: Uuid,
        expected_current_metadata_key_id: Uuid,
        new_metadata_key_id: Uuid,
        metadata_ciphertext: &[u8],
        metadata_nonce: &[u8],
    ) -> Result<bool, RepoError> {
        let resultado = sqlx::query(
            "update resources set metadata_ciphertext = ?1, metadata_nonce = ?2, metadata_key_id = ?3 \
             where id = ?4 and metadata_key_id = ?5 and deleted_at is null",
        )
        .bind(metadata_ciphertext)
        .bind(metadata_nonce)
        .bind(new_metadata_key_id.to_string())
        .bind(resource_id.to_string())
        .bind(expected_current_metadata_key_id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(resultado.rows_affected() == 1)
    }

    async fn actualizar(
        &self,
        resource_id: Uuid,
        expected_updated_at: OffsetDateTime,
        metadata_ciphertext: &[u8],
        metadata_nonce: &[u8],
        envelopes: &[EnvelopeInput],
    ) -> Result<Option<Resource>, RepoError> {
        let mut tx = self.pool.begin().await?;
        let ahora = fmt_dt(nueva_version(expected_updated_at));

        let resultado = sqlx::query(
            "update resources set metadata_ciphertext = ?1, metadata_nonce = ?2, updated_at = ?3 \
             where id = ?4 and updated_at = ?5 and deleted_at is null",
        )
        .bind(metadata_ciphertext)
        .bind(metadata_nonce)
        .bind(&ahora)
        .bind(resource_id.to_string())
        .bind(fmt_dt(expected_updated_at))
        .execute(&mut *tx)
        .await?;

        if resultado.rows_affected() != 1 {
            return Ok(None);
        }

        sqlx::query("delete from secret_envelopes where resource_id = ?1")
            .bind(resource_id.to_string())
            .execute(&mut *tx)
            .await?;

        for env in envelopes {
            sqlx::query(
                "insert into secret_envelopes (id, resource_id, user_id, sealed_dek, secret_ciphertext, secret_nonce) \
                 values (?1,?2,?3,?4,?5,?6)",
            )
            .bind(Uuid::now_v7().to_string())
            .bind(resource_id.to_string())
            .bind(env.user_id.to_string())
            .bind(&env.sealed_dek)
            .bind(&env.secret_ciphertext)
            .bind(&env.secret_nonce)
            .execute(&mut *tx)
            .await?;
        }

        let fila = sqlx::query(
            "select id, resource_type_id, metadata_ciphertext, metadata_nonce, created_by, created_at, \
             updated_at, metadata_key_type, metadata_key_id from resources where id = ?1",
        )
        .bind(resource_id.to_string())
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(Some(fila_a_resource(&fila)?))
    }

    async fn listar_destinatarios(&self, resource_id: Uuid) -> Result<Vec<Destinatario>, RepoError> {
        let filas = sqlx::query(
            "select se.user_id as user_id, uk.public_key_x25519 as public_key_x25519 \
             from secret_envelopes se join user_keys uk on uk.user_id = se.user_id \
             where se.resource_id = ?1",
        )
        .bind(resource_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        filas
            .iter()
            .map(|f| -> Result<_, RepoError> {
                Ok(Destinatario {
                    user_id: parse_uuid(f.try_get::<String, _>("user_id")?.as_str())?,
                    public_key_x25519: f.get("public_key_x25519"),
                })
            })
            .collect()
    }

    async fn tocar_updated_at(&self, resource_id: Uuid) -> Result<(), RepoError> {
        sqlx::query("update resources set updated_at = ?2 where id = ?1")
            .bind(resource_id.to_string())
            .bind(fmt_dt(OffsetDateTime::now_utc()))
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}

impl SqliteResourceRepository {
    /// F-48 (modos `Memory`/`NamesOnly`, spec/13 §8): variante de
    /// `actualizar` que sólo reemplaza metadata — nunca toca
    /// `secret_envelopes`. Usada cuando el pull de sync trae un recurso cuyo
    /// secreto no se replica localmente en este modo; el DEK sellado que sí
    /// hace falta para descifrar la metadata vive aparte, en
    /// `metadata_deks` (`SqliteMetadataDekRepository`). Mismo lock optimista
    /// que `actualizar` — `Ok(None)` si `expected_updated_at` no matchea.
    pub async fn actualizar_metadata_solo(
        &self,
        resource_id: Uuid,
        expected_updated_at: OffsetDateTime,
        metadata_ciphertext: &[u8],
        metadata_nonce: &[u8],
    ) -> Result<Option<Resource>, RepoError> {
        let ahora = fmt_dt(nueva_version(expected_updated_at));
        let resultado = sqlx::query(
            "update resources set metadata_ciphertext = ?1, metadata_nonce = ?2, updated_at = ?3 \
             where id = ?4 and updated_at = ?5 and deleted_at is null",
        )
        .bind(metadata_ciphertext)
        .bind(metadata_nonce)
        .bind(&ahora)
        .bind(resource_id.to_string())
        .bind(fmt_dt(expected_updated_at))
        .execute(&self.pool)
        .await?;

        if resultado.rows_affected() != 1 {
            return Ok(None);
        }

        let fila = sqlx::query(
            "select id, resource_type_id, metadata_ciphertext, metadata_nonce, created_by, created_at, \
             updated_at, metadata_key_type, metadata_key_id from resources where id = ?1",
        )
        .bind(resource_id.to_string())
        .fetch_one(&self.pool)
        .await?;
        Ok(Some(fila_a_resource(&fila)?))
    }
}

#[derive(Clone)]
pub struct SqliteResourceTypeRepository {
    pub pool: SqlitePool,
}

impl ResourceTypeRepository for SqliteResourceTypeRepository {
    async fn id_por_slug(&self, slug: &str) -> Result<Option<Uuid>, RepoError> {
        let fila = sqlx::query("select id from resource_types where slug = ?1 and deleted_at is null")
            .bind(slug)
            .fetch_optional(&self.pool)
            .await?;
        fila.map(|f| parse_uuid(f.try_get::<String, _>("id")?.as_str())).transpose()
    }

    async fn mapa_id_a_slug(&self) -> Result<std::collections::HashMap<Uuid, String>, RepoError> {
        let filas = sqlx::query("select id, slug from resource_types where deleted_at is null")
            .fetch_all(&self.pool)
            .await?;
        filas
            .iter()
            .map(|f| -> Result<_, RepoError> { Ok((parse_uuid(f.try_get::<String, _>("id")?.as_str())?, f.get("slug"))) })
            .collect()
    }

    async fn json_schema_por_id(&self, id: Uuid) -> Result<Option<serde_json::Value>, RepoError> {
        let fila = sqlx::query("select json_schema from resource_types where id = ?1 and deleted_at is null")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        fila.map(|f| {
            let texto: String = f.get("json_schema");
            serde_json::from_str(&texto).map_err(|e| RepoError::Database(sqlx::Error::Decode(Box::new(e))))
        })
        .transpose()
    }
}

#[derive(Clone)]
pub struct SqliteSecretEnvelopeRepository {
    pub pool: SqlitePool,
}

impl SecretEnvelopeRepository for SqliteSecretEnvelopeRepository {
    async fn insertar(
        &self,
        resource_id: Uuid,
        user_id: Uuid,
        sealed_dek: &[u8],
        secret_ciphertext: &[u8],
        secret_nonce: &[u8],
    ) -> Result<(), RepoError> {
        let resultado = sqlx::query(
            "insert into secret_envelopes (id, resource_id, user_id, sealed_dek, secret_ciphertext, secret_nonce) \
             values (?1,?2,?3,?4,?5,?6)",
        )
        .bind(Uuid::now_v7().to_string())
        .bind(resource_id.to_string())
        .bind(user_id.to_string())
        .bind(sealed_dek)
        .bind(secret_ciphertext)
        .bind(secret_nonce)
        .execute(&self.pool)
        .await;

        if let Err(sqlx::Error::Database(db)) = &resultado
            && db.is_unique_violation()
        {
            return Err(RepoError::Conflict);
        }
        resultado?;
        Ok(())
    }

    async fn buscar(&self, resource_id: Uuid, user_id: Uuid) -> Result<Option<SecretEnvelope>, RepoError> {
        let fila = sqlx::query(
            "select sealed_dek, secret_ciphertext, secret_nonce from secret_envelopes \
             where resource_id = ?1 and user_id = ?2",
        )
        .bind(resource_id.to_string())
        .bind(user_id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        Ok(fila.map(|f| SecretEnvelope {
            sealed_dek: f.get("sealed_dek"),
            secret_ciphertext: f.get("secret_ciphertext"),
            secret_nonce: f.get("secret_nonce"),
        }))
    }
}

/// F-48: DEK sellado de un recurso cuyo secreto NO está replicado
/// localmente (modos `Memory`/`NamesOnly`, spec/13 §8) — separado de
/// `secret_envelopes` a propósito, ver comentario de la migración
/// `0007_metadata_deks.sql`. No implementa un trait compartido: es un
/// concepto 100% del modo escritorio, sin equivalente Postgres.
#[derive(Clone)]
pub struct SqliteMetadataDekRepository {
    pub pool: SqlitePool,
}

impl SqliteMetadataDekRepository {
    pub async fn guardar(&self, resource_id: Uuid, user_id: Uuid, sealed_dek: &[u8]) -> Result<(), RepoError> {
        sqlx::query(
            "insert into metadata_deks (resource_id, user_id, sealed_dek) values (?1,?2,?3) \
             on conflict(resource_id) do update set user_id = excluded.user_id, sealed_dek = excluded.sealed_dek",
        )
        .bind(resource_id.to_string())
        .bind(user_id.to_string())
        .bind(sealed_dek)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn buscar(&self, resource_id: Uuid, user_id: Uuid) -> Result<Option<Vec<u8>>, RepoError> {
        let fila = sqlx::query("select sealed_dek from metadata_deks where resource_id = ?1 and user_id = ?2")
            .bind(resource_id.to_string())
            .bind(user_id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        Ok(fila.map(|f| f.get("sealed_dek")))
    }
}

#[derive(Clone)]
pub struct SqlitePermissionRepository {
    pub pool: SqlitePool,
}

impl SqlitePermissionRepository {
    async fn es_dueno(&self, resource_id: Uuid, user_id: Uuid) -> Result<bool, RepoError> {
        let fila = sqlx::query("select 1 as x from resources where id = ?1 and created_by = ?2 and deleted_at is null")
            .bind(resource_id.to_string())
            .bind(user_id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        Ok(fila.is_some())
    }
}

impl PermissionRepository for SqlitePermissionRepository {
    async fn otorgar(&self, _subject_type: &str, _subject_id: Uuid, _grantee_type: &str, _grantee_id: Uuid, _nivel: &str) -> Result<(), RepoError> {
        // No-op: la propiedad ya está implícita en `resources.created_by`,
        // sin tabla `permissions` en este modo (spec/13 §5).
        Ok(())
    }

    async fn tiene_permiso(&self, subject_type: &str, subject_id: Uuid, user_id: Uuid, _nivel_minimo: &str) -> Result<bool, RepoError> {
        match subject_type {
            "resource" => self.es_dueno(subject_id, user_id).await,
            // "folder": folders todavía no migrado en este modo.
            _ => Ok(false),
        }
    }

    async fn recursos_por_grantee(&self, _grantee_type: &str, _grantee_id: Uuid) -> Result<Vec<Uuid>, RepoError> {
        Ok(Vec::new())
    }

    async fn existe_otro_owner(&self, _subject_type: &str, _subject_id: Uuid, _excluir_grantee_type: &str, _excluir_grantee_id: Uuid) -> Result<bool, RepoError> {
        Ok(false)
    }

    async fn subjects_owner_de(&self, _grantee_type: &str, _grantee_id: Uuid) -> Result<Vec<(String, Uuid)>, RepoError> {
        Ok(Vec::new())
    }

    async fn existe_algun_permiso(&self, _subject_type: &str, _subject_id: Uuid) -> Result<bool, RepoError> {
        Ok(false)
    }

    async fn grupo_grantee_de(&self, _subject_type: &str, _subject_id: Uuid) -> Result<Option<Uuid>, RepoError> {
        Ok(None)
    }

    async fn listar(&self, subject_type: &str, subject_id: Uuid) -> Result<Vec<PermisoGrantee>, RepoError> {
        if subject_type != "resource" {
            return Ok(Vec::new());
        }
        let fila = sqlx::query("select created_by from resources where id = ?1 and deleted_at is null")
            .bind(subject_id.to_string())
            .fetch_optional(&self.pool)
            .await?;
        Ok(match fila {
            Some(f) => vec![PermisoGrantee {
                grantee_type: "user".to_string(),
                grantee_id: parse_uuid(f.try_get::<String, _>("created_by")?.as_str())?,
                level: "owner".to_string(),
                label: None,
            }],
            None => Vec::new(),
        })
    }

    async fn revocar(&self, _subject_type: &str, _subject_id: Uuid, _grantee_type: &str, _grantee_id: Uuid) -> Result<(), RepoError> {
        Ok(())
    }

    async fn revocar_si_queda_otro_owner(&self, _subject_type: &str, _subject_id: Uuid, _grantee_type: &str, _grantee_id: Uuid) -> Result<bool, RepoError> {
        // Único owner posible en este modo (el dueño) — revocarlo siempre
        // dejaría el recurso sin ninguno, se rechaza (mismo criterio que la
        // versión Postgres, H-26).
        Ok(false)
    }

    async fn cambiar_nivel_si_queda_otro_owner(&self, _subject_type: &str, _subject_id: Uuid, _grantee_type: &str, _grantee_id: Uuid, _nuevo_nivel: &str) -> Result<bool, RepoError> {
        Ok(false)
    }
}
