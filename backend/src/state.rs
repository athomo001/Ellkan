// Autor: Athan Espinoza

use std::num::NonZeroU32;
use std::sync::Arc;

use governor::{DefaultKeyedRateLimiter, Quota};
use uuid::Uuid;

use crate::admin::repository::PgRoleRepository;
use crate::auth::repository::{
    PgAuthChallengeRepository, PgDeviceChallengeRepository, PgKnownDeviceRepository,
    PgSessionRepository, PgUserRepository,
};
use crate::devices::repository::{
    PgApprovalRequestRepository, PgDeviceApprovalPolicyRepository, PgTrustedDeviceRepository,
};
use crate::eventos::{self, EmisorDeEventos};
use crate::folders::repository::{PgFolderItemRepository, PgFolderRepository};
use crate::groups::repository::{PgGroupMemberRepository, PgGroupRepository, PgOrganizationRepository};
use crate::metadata::repository::{PgMetadataKeyEnvelopeRepository, PgMetadataKeyRepository};
use crate::notificaciones::PgOutboundEmailRepository;
use crate::passkeys::repository::{PgCeremonyStateRepository, PgPasskeyRepository};
use crate::resources::repository::{
    PgPermissionRepository, PgResourceRepository, PgResourceTypeRepository,
    PgSecretEnvelopeRepository,
};
use crate::tags::repository::PgTagRepository;

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
    pub roles: PgRoleRepository,
    pub carpetas: PgFolderRepository,
    pub items_de_carpeta: PgFolderItemRepository,
    pub tags: PgTagRepository,
    pub claves_metadata: PgMetadataKeyRepository,
    pub envelopes_metadata: PgMetadataKeyEnvelopeRepository,
    pub grupos: PgGroupRepository,
    pub miembros_de_grupo: PgGroupMemberRepository,
    pub organizacion: PgOrganizationRepository,
    pub passkeys: PgPasskeyRepository,
    pub ceremonias_webauthn: PgCeremonyStateRepository,
    pub dispositivos_confiables: PgTrustedDeviceRepository,
    pub solicitudes_aprobacion: PgApprovalRequestRepository,
    pub politica_aprobacion_dispositivo: PgDeviceApprovalPolicyRepository,
    /// F-03: instancia única del RP WebAuthn — `rp_id`/origin se leen de
    /// `ELLKAN_RP_ID`/`ELLKAN_RP_ORIGIN` (default de desarrollo
    /// `localhost`/`http://localhost:8080`). **Producción debe fijar
    /// ambas** a su origen HTTPS real: la validación de origin es la
    /// propiedad anti-phishing central de WebAuthn, no un detalle
    /// cosmético — con el default, cualquier origin sería aceptado como
    /// "localhost", lo que no tiene sentido fuera de desarrollo.
    pub webauthn: Arc<webauthn_rs::prelude::Webauthn>,
    /// Rate limiting por `user_id` autenticado — capa adicional sobre el
    /// `GovernorLayer` por IP de `lib.rs`, no un reemplazo.
    /// `governor::RateLimiter::keyed` en vez de otro
    /// `tower_governor::GovernorLayer` porque ese layer corre antes de que
    /// exista `AuthenticatedUser` (no tiene forma de extraer `user_id`).
    pub limitador_por_usuario: Arc<DefaultKeyedRateLimiter<Uuid>>,
}

/// Lee `ELLKAN_RP_ID`/`ELLKAN_RP_ORIGIN` con default de desarrollo — ver el
/// comentario de `AppState::webauthn` sobre por qué producción no puede
/// quedarse con ese default.
fn construir_webauthn() -> webauthn_rs::prelude::Webauthn {
    let rp_id = std::env::var("ELLKAN_RP_ID").unwrap_or_else(|_| "localhost".to_string());
    let rp_origin_str = std::env::var("ELLKAN_RP_ORIGIN").unwrap_or_else(|_| "http://localhost:8080".to_string());
    let rp_origin = webauthn_rs::prelude::Url::parse(&rp_origin_str).expect("ELLKAN_RP_ORIGIN debe ser una URL válida");

    webauthn_rs::prelude::WebauthnBuilder::new(&rp_id, &rp_origin)
        .expect("ELLKAN_RP_ID/ELLKAN_RP_ORIGIN deben ser consistentes entre sí")
        .rp_name("Ellkan")
        .build()
        .expect("configuración de Webauthn válida")
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
            roles: PgRoleRepository { pool: pool.clone() },
            carpetas: PgFolderRepository { pool: pool.clone() },
            items_de_carpeta: PgFolderItemRepository { pool: pool.clone() },
            tags: PgTagRepository { pool: pool.clone() },
            claves_metadata: PgMetadataKeyRepository { pool: pool.clone() },
            envelopes_metadata: PgMetadataKeyEnvelopeRepository { pool: pool.clone() },
            grupos: PgGroupRepository { pool: pool.clone() },
            miembros_de_grupo: PgGroupMemberRepository { pool: pool.clone() },
            organizacion: PgOrganizationRepository { pool: pool.clone() },
            passkeys: PgPasskeyRepository { pool: pool.clone() },
            ceremonias_webauthn: PgCeremonyStateRepository { pool: pool.clone() },
            dispositivos_confiables: PgTrustedDeviceRepository { pool: pool.clone() },
            solicitudes_aprobacion: PgApprovalRequestRepository { pool: pool.clone() },
            politica_aprobacion_dispositivo: PgDeviceApprovalPolicyRepository { pool: pool.clone() },
            webauthn: Arc::new(construir_webauthn()),
            server_public_key_ed25519: Arc::new(server_public_key_ed25519),
            limitador_por_usuario: Arc::new(governor::RateLimiter::keyed(cuota)),
            pool,
        }
    }
}
