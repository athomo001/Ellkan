// Autor: Athan Espinoza

#![allow(async_fn_in_trait)]

use std::future::Future;

use uuid::Uuid;

use crate::error::RepoError;

use super::models::{MetadataKey, MetadataKeyEnvelope};

// `Send` explícito (en vez de `async fn`, mismo criterio que
// `OutboundEmailRepository` en `notificaciones.rs`): el consumidor de F-33
// vigila una rotación dentro de una tarea `tokio::spawn` genérica sobre este
// trait, y `async fn` en un trait no garantiza `Send` por sí solo.
pub trait MetadataKeyRepository {
    fn buscar(&self, id: Uuid) -> impl Future<Output = Result<Option<MetadataKey>, RepoError>> + Send;

    /// Hasta 2 filas con `expired_at is null` — la saliente y la entrante
    /// durante una rotación (F-33), o sólo 1 fuera de rotación.
    fn activas(&self) -> impl Future<Output = Result<Vec<MetadataKey>, RepoError>> + Send;

    /// Usado por `system_status` como chequeo rápido de salud del subsistema
    /// de rotación — `crear_si_no_excede`/`iniciar_rotacion_atomico` (H-29)
    /// son las únicas vías de alta real, esto queda sólo para lectura.
    fn contar_activas(&self) -> impl Future<Output = Result<i64, RepoError>> + Send;

    fn marcar_expirada(&self, id: Uuid) -> impl Future<Output = Result<(), RepoError>> + Send;

    /// F-33: cuántos recursos (no borrados) siguen cifrados con esta clave —
    /// se recalcula en vivo en cada consulta, nunca se cachea, para que la
    /// migración sea reintentable sin estado propio: si el proceso se
    /// reinicia a mitad de una rotación, este conteo ya refleja el progreso
    /// real sin tener que retomar ningún cursor guardado.
    fn contar_recursos_con_clave(&self, metadata_key_id: Uuid) -> impl Future<Output = Result<i64, RepoError>> + Send;

    fn marcar_pendientes_al_iniciar(
        &self,
        id: Uuid,
        total: i64,
    ) -> impl Future<Output = Result<(), RepoError>> + Send;

    /// H-29 (auditoría 2026-08-12): versión atómica de `contar_activas` +
    /// `crear` — el `Service` antes hacía las dos queries sueltas, con una
    /// ventana de carrera real (dos altas concurrentes podían ambas ver
    /// "menos de 2 activas" y terminar con 3+, corrompiendo el invariante
    /// `MaxNoOfActiveMetadataKeysRule`). `None` = ya había `limite` o más
    /// activas, no se creó nada.
    fn crear_si_no_excede(
        &self,
        id: Uuid,
        public_key_x25519: &[u8],
        fingerprint: &str,
        limite: i64,
    ) -> impl Future<Output = Result<Option<MetadataKey>, RepoError>> + Send;

    /// H-29: versión atómica de `activas` (exige exactamente 1) + `crear` +
    /// `marcar_pendientes_al_iniciar`, todo bajo el mismo lock de fila —
    /// evita que dos `iniciar_rotacion` concurrentes vean ambas "1 activa"
    /// y cada una cree su propia entrante. `None` = no había exactamente 1
    /// clave activa (nada que rotar, o ya hay una rotación en curso).
    fn iniciar_rotacion_atomico(
        &self,
        id_entrante: Uuid,
        public_key_x25519: &[u8],
        fingerprint: &str,
    ) -> impl Future<Output = Result<Option<(MetadataKey, MetadataKey, i64)>, RepoError>> + Send;
}

pub trait MetadataKeyEnvelopeRepository {
    async fn insertar(
        &self,
        metadata_key_id: Uuid,
        user_id: Uuid,
        sealed_private_key: &[u8],
    ) -> Result<(), RepoError>;

    async fn buscar(
        &self,
        metadata_key_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<MetadataKeyEnvelope>, RepoError>;
}

#[derive(Clone)]
pub struct PgMetadataKeyRepository {
    pub pool: sqlx::PgPool,
}

impl MetadataKeyRepository for PgMetadataKeyRepository {
    async fn buscar(&self, id: Uuid) -> Result<Option<MetadataKey>, RepoError> {
        let fila = sqlx::query!(
            r#"
            select id, public_key_x25519, fingerprint, expired_at, resources_pendientes_al_iniciar
            from metadata_keys
            where id = $1 and deleted_at is null
            "#,
            id,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(fila.map(|f| MetadataKey {
            id: f.id,
            public_key_x25519: f.public_key_x25519,
            fingerprint: f.fingerprint,
            expired_at: f.expired_at,
            resources_pendientes_al_iniciar: f.resources_pendientes_al_iniciar,
        }))
    }

    async fn activas(&self) -> Result<Vec<MetadataKey>, RepoError> {
        let filas = sqlx::query!(
            r#"
            select id, public_key_x25519, fingerprint, expired_at, resources_pendientes_al_iniciar
            from metadata_keys
            where expired_at is null and deleted_at is null
            order by id
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(filas
            .into_iter()
            .map(|f| MetadataKey {
                id: f.id,
                public_key_x25519: f.public_key_x25519,
                fingerprint: f.fingerprint,
                expired_at: f.expired_at,
                resources_pendientes_al_iniciar: f.resources_pendientes_al_iniciar,
            })
            .collect())
    }

    async fn contar_activas(&self) -> Result<i64, RepoError> {
        let fila = sqlx::query!(
            r#"select count(*) as "n!" from metadata_keys where expired_at is null and deleted_at is null"#,
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(fila.n)
    }

    async fn marcar_expirada(&self, id: Uuid) -> Result<(), RepoError> {
        sqlx::query!(r#"update metadata_keys set expired_at = now() where id = $1"#, id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn contar_recursos_con_clave(&self, metadata_key_id: Uuid) -> Result<i64, RepoError> {
        let fila = sqlx::query!(
            r#"select count(*) as "n!" from resources where metadata_key_id = $1 and deleted_at is null"#,
            metadata_key_id,
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(fila.n)
    }

    async fn marcar_pendientes_al_iniciar(&self, id: Uuid, total: i64) -> Result<(), RepoError> {
        sqlx::query!(
            r#"update metadata_keys set resources_pendientes_al_iniciar = $2 where id = $1"#,
            id,
            total as i32,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn crear_si_no_excede(
        &self,
        id: Uuid,
        public_key_x25519: &[u8],
        fingerprint: &str,
        limite: i64,
    ) -> Result<Option<MetadataKey>, RepoError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query!(r#"select 1 as "x!" from metadata_keys where expired_at is null and deleted_at is null for update"#)
            .fetch_all(&mut *tx)
            .await?;

        let activas: i64 =
            sqlx::query!(r#"select count(*) as "n!" from metadata_keys where expired_at is null and deleted_at is null"#)
                .fetch_one(&mut *tx)
                .await?
                .n;
        if activas >= limite {
            tx.rollback().await?;
            return Ok(None);
        }

        let fila = sqlx::query!(
            r#"
            insert into metadata_keys (id, public_key_x25519, fingerprint)
            values ($1, $2, $3)
            returning id, public_key_x25519, fingerprint, expired_at, resources_pendientes_al_iniciar
            "#,
            id,
            public_key_x25519,
            fingerprint,
        )
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;

        Ok(Some(MetadataKey {
            id: fila.id,
            public_key_x25519: fila.public_key_x25519,
            fingerprint: fila.fingerprint,
            expired_at: fila.expired_at,
            resources_pendientes_al_iniciar: fila.resources_pendientes_al_iniciar,
        }))
    }

    async fn iniciar_rotacion_atomico(
        &self,
        id_entrante: Uuid,
        public_key_x25519: &[u8],
        fingerprint: &str,
    ) -> Result<Option<(MetadataKey, MetadataKey, i64)>, RepoError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query!(r#"select 1 as "x!" from metadata_keys where expired_at is null and deleted_at is null for update"#)
            .fetch_all(&mut *tx)
            .await?;

        let activas = sqlx::query!(
            r#"
            select id, public_key_x25519, fingerprint, expired_at, resources_pendientes_al_iniciar
            from metadata_keys
            where expired_at is null and deleted_at is null
            order by id
            "#,
        )
        .fetch_all(&mut *tx)
        .await?;

        let [saliente_fila] = activas.as_slice() else {
            tx.rollback().await?;
            return Ok(None);
        };
        let saliente = MetadataKey {
            id: saliente_fila.id,
            public_key_x25519: saliente_fila.public_key_x25519.clone(),
            fingerprint: saliente_fila.fingerprint.clone(),
            expired_at: saliente_fila.expired_at,
            resources_pendientes_al_iniciar: saliente_fila.resources_pendientes_al_iniciar,
        };

        let total_pendiente: i64 =
            sqlx::query!(r#"select count(*) as "n!" from resources where metadata_key_id = $1 and deleted_at is null"#, saliente.id)
                .fetch_one(&mut *tx)
                .await?
                .n;

        let entrante_fila = sqlx::query!(
            r#"
            insert into metadata_keys (id, public_key_x25519, fingerprint)
            values ($1, $2, $3)
            returning id, public_key_x25519, fingerprint, expired_at, resources_pendientes_al_iniciar
            "#,
            id_entrante,
            public_key_x25519,
            fingerprint,
        )
        .fetch_one(&mut *tx)
        .await?;
        let entrante = MetadataKey {
            id: entrante_fila.id,
            public_key_x25519: entrante_fila.public_key_x25519,
            fingerprint: entrante_fila.fingerprint,
            expired_at: entrante_fila.expired_at,
            resources_pendientes_al_iniciar: entrante_fila.resources_pendientes_al_iniciar,
        };

        sqlx::query!(
            r#"update metadata_keys set resources_pendientes_al_iniciar = $2 where id = $1"#,
            saliente.id,
            total_pendiente as i32,
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(Some((saliente, entrante, total_pendiente)))
    }
}

#[derive(Clone)]
pub struct PgMetadataKeyEnvelopeRepository {
    pub pool: sqlx::PgPool,
}

impl MetadataKeyEnvelopeRepository for PgMetadataKeyEnvelopeRepository {
    async fn insertar(
        &self,
        metadata_key_id: Uuid,
        user_id: Uuid,
        sealed_private_key: &[u8],
    ) -> Result<(), RepoError> {
        sqlx::query!(
            r#"
            insert into metadata_key_envelopes (metadata_key_id, user_id, sealed_private_key)
            values ($1, $2, $3)
            "#,
            metadata_key_id,
            user_id,
            sealed_private_key,
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
        metadata_key_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<MetadataKeyEnvelope>, RepoError> {
        let fila = sqlx::query!(
            r#"
            select sealed_private_key from metadata_key_envelopes
            where metadata_key_id = $1 and user_id = $2
            "#,
            metadata_key_id,
            user_id,
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(fila.map(|f| MetadataKeyEnvelope { sealed_private_key: f.sealed_private_key }))
    }
}
