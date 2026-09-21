// Autor: Athan Espinoza

//! `AppState` del modo escritorio — deliberadamente **no** el `AppState` de
//! `state.rs` (ese sigue siendo 100% Postgres/modo servidor, sin tocar).
//! Módulos ya migrados a SQLite: `auth`, `mfa`, `smtp_config`,
//! `self_registration`, `recovery_kit`, `resources`/`secret_envelopes`/
//! `resource_types`, `folders`/`folder_items` (real desde 2026-09-16, antes
//! stub), `tags`/`resource_tags` (nuevo 2026-09-16) — `groups`/`admin`
//! (roles) quedan como stubs triviales a propósito (spec/13 §3: esos módulos
//! se compilan afuera del binario completo, acá sólo hace falta que el
//! trait compile para que `FolderService`/`ResourceService` sigan siendo
//! genéricos). El resto de los repositorios de `state.rs::AppState` no
//! tiene todavía implementación SQLite, así que no puede construirse sin un
//! `PgPool` que este modo no tiene. Se amplía módulo por módulo a medida que
//! cada uno se migre (spec/05 "Fase de escritorio" 3.1, próximos pasos).

use std::sync::Arc;

use sqlx::SqlitePool;

use crate::desktop::repositories::admin::SqliteRoleRepository;
use crate::desktop::repositories::auth::{
    SqliteAuthChallengeRepository, SqliteDeviceChallengeRepository, SqliteKnownDeviceRepository,
    SqliteSessionRepository, SqliteUserRepository,
};
use crate::desktop::repositories::folders::{SqliteFolderItemRepository, SqliteFolderRepository};
use crate::desktop::repositories::groups::SqliteGroupMemberRepository;
use crate::desktop::repositories::mfa::{SqliteMfaChallengeRepository, SqliteMfaPolicyRepository, SqliteTotpCredentialRepository};
use crate::desktop::repositories::recovery_kit::{SqliteRecoveryKitRepository, SqliteResetTokenRepository};
use crate::desktop::repositories::resources::{
    SqliteMetadataDekRepository, SqlitePermissionRepository, SqliteResourceRepository, SqliteResourceTypeRepository,
    SqliteSecretEnvelopeRepository,
};
use crate::desktop::repositories::self_registration::SqliteSelfRegistrationPolicyRepository;
use crate::desktop::repositories::smtp_config::SqliteSmtpConfigRepository;
use std::path::PathBuf;

use crate::desktop::repositories::tags::SqliteTagRepository;
use crate::eventos::{self, EmisorDeEventos};
use ellkan_crypto::secretos::ClaveSecreta32;

#[derive(Clone)]
pub struct AppStateDesktop {
    pub datadir: Arc<PathBuf>,
    pub pool: SqlitePool,
    pub server_public_key_ed25519: Arc<[u8; 32]>,
    pub usuarios: SqliteUserRepository,
    pub challenges: SqliteAuthChallengeRepository,
    pub sesiones: SqliteSessionRepository,
    pub dispositivos: SqliteKnownDeviceRepository,
    pub desafios_dispositivo: SqliteDeviceChallengeRepository,
    pub mfa_policy: SqliteMfaPolicyRepository,
    pub mfa_totp: SqliteTotpCredentialRepository,
    pub mfa_challenges: SqliteMfaChallengeRepository,
    pub smtp_config: SqliteSmtpConfigRepository,
    pub self_registration_policy: SqliteSelfRegistrationPolicyRepository,
    pub recovery_kits: SqliteRecoveryKitRepository,
    pub recovery_reset_tokens: SqliteResetTokenRepository,
    pub recursos: SqliteResourceRepository,
    pub envolturas: SqliteSecretEnvelopeRepository,
    pub metadata_deks: SqliteMetadataDekRepository,
    pub permisos: SqlitePermissionRepository,
    pub tipos_recurso: SqliteResourceTypeRepository,
    pub carpetas: SqliteFolderRepository,
    pub items_de_carpeta: SqliteFolderItemRepository,
    pub tags: SqliteTagRepository,
    pub miembros_de_grupo: SqliteGroupMemberRepository,
    pub roles: SqliteRoleRepository,
    pub eventos: EmisorDeEventos,
    /// F-14: misma clave maestra de servidor que la versión Postgres usa
    /// para cifrar el secreto TOTP en reposo.
    pub secrets_key: Arc<ClaveSecreta32>,
}

impl AppStateDesktop {
    pub fn nuevo(datadir: PathBuf, pool: SqlitePool, server_public_key_ed25519: [u8; 32], secrets_key: ClaveSecreta32) -> Self {
        Self {
            datadir: Arc::new(datadir),
            usuarios: SqliteUserRepository { pool: pool.clone() },
            challenges: SqliteAuthChallengeRepository { pool: pool.clone() },
            sesiones: SqliteSessionRepository { pool: pool.clone() },
            dispositivos: SqliteKnownDeviceRepository { pool: pool.clone() },
            desafios_dispositivo: SqliteDeviceChallengeRepository { pool: pool.clone() },
            mfa_policy: SqliteMfaPolicyRepository,
            mfa_totp: SqliteTotpCredentialRepository { pool: pool.clone() },
            mfa_challenges: SqliteMfaChallengeRepository { pool: pool.clone() },
            smtp_config: SqliteSmtpConfigRepository,
            self_registration_policy: SqliteSelfRegistrationPolicyRepository,
            recovery_kits: SqliteRecoveryKitRepository { pool: pool.clone() },
            recovery_reset_tokens: SqliteResetTokenRepository { pool: pool.clone() },
            recursos: SqliteResourceRepository { pool: pool.clone() },
            envolturas: SqliteSecretEnvelopeRepository { pool: pool.clone() },
            metadata_deks: SqliteMetadataDekRepository { pool: pool.clone() },
            permisos: SqlitePermissionRepository { pool: pool.clone() },
            tipos_recurso: SqliteResourceTypeRepository { pool: pool.clone() },
            carpetas: SqliteFolderRepository { pool: pool.clone() },
            items_de_carpeta: SqliteFolderItemRepository { pool: pool.clone() },
            tags: SqliteTagRepository { pool: pool.clone() },
            miembros_de_grupo: SqliteGroupMemberRepository,
            roles: SqliteRoleRepository,
            eventos: eventos::nuevo_canal(),
            secrets_key: Arc::new(secrets_key),
            server_public_key_ed25519: Arc::new(server_public_key_ed25519),
            pool,
        }
    }
}
