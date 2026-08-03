// Autor: Athan Espinoza

use std::num::NonZeroU32;
use std::sync::Arc;

use governor::{DefaultKeyedRateLimiter, Quota};
use uuid::Uuid;

use crate::auth::repository::{
    PgAuthChallengeRepository, PgDeviceChallengeRepository, PgKnownDeviceRepository,
    PgSessionRepository, PgUserRepository,
};
use crate::eventos::{self, EmisorDeEventos};
use crate::notificaciones::PgOutboundEmailRepository;
use crate::resources::repository::{
    PgPermissionRepository, PgResourceRepository, PgResourceTypeRepository,
    PgSecretEnvelopeRepository,
};

#[derive(Clone)]
pub struct AppState {
    pub pool: sqlx::PgPool,
    pub server_public_key_ed25519: Arc<[u8; 32]>,
    pub usuarios: PgUserRepository,
    pub challenges: PgAuthChallengeRepository,
    pub sesiones: PgSessionRepository,
    pub dispositivos: PgKnownDeviceRepository,
    pub desafios_dispositivo: PgDeviceChallengeRepository,
    pub emails: PgOutboundEmailRepository,
    pub eventos: EmisorDeEventos,
    pub recursos: PgResourceRepository,
    pub tipos_recurso: PgResourceTypeRepository,
    pub envolturas: PgSecretEnvelopeRepository,
    pub permisos: PgPermissionRepository,
    /// Rate limiting por `user_id` autenticado — capa adicional sobre el
    /// `GovernorLayer` por IP de `lib.rs`, no un reemplazo.
    /// `governor::RateLimiter::keyed` en vez de otro
    /// `tower_governor::GovernorLayer` porque ese layer corre antes de que
    /// exista `AuthenticatedUser` (no tiene forma de extraer `user_id`).
    pub limitador_por_usuario: Arc<DefaultKeyedRateLimiter<Uuid>>,
}

impl AppState {
    pub fn nuevo(pool: sqlx::PgPool, server_public_key_ed25519: [u8; 32]) -> Self {
        let cuota = Quota::per_second(NonZeroU32::new(10).expect("10 no es cero"))
            .allow_burst(NonZeroU32::new(20).expect("20 no es cero"));
        Self {
            usuarios: PgUserRepository { pool: pool.clone() },
            challenges: PgAuthChallengeRepository { pool: pool.clone() },
            sesiones: PgSessionRepository { pool: pool.clone() },
            dispositivos: PgKnownDeviceRepository { pool: pool.clone() },
            desafios_dispositivo: PgDeviceChallengeRepository { pool: pool.clone() },
            emails: PgOutboundEmailRepository { pool: pool.clone() },
            eventos: eventos::nuevo_canal(),
            recursos: PgResourceRepository { pool: pool.clone() },
            tipos_recurso: PgResourceTypeRepository { pool: pool.clone() },
            envolturas: PgSecretEnvelopeRepository { pool: pool.clone() },
            permisos: PgPermissionRepository { pool: pool.clone() },
            server_public_key_ed25519: Arc::new(server_public_key_ed25519),
            limitador_por_usuario: Arc::new(governor::RateLimiter::keyed(cuota)),
            pool,
        }
    }
}
