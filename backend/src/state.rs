// Autor: Athan Espinoza

use std::num::NonZeroU32;
use std::sync::Arc;

use governor::{DefaultKeyedRateLimiter, Quota};
use uuid::Uuid;

use crate::account_recovery::repository::{
    PgAccountRecoveryPolicyRepository, PgEscrowRepository, PgOrgRecoveryKeyRepository,
    PgRecoveryRequestRepository,
};
use crate::admin::repository::PgRoleRepository;
use crate::audit::repository::PgAuditLogRepository;
use crate::auth::repository::{
    PgAuthChallengeRepository, PgDeviceChallengeRepository, PgKnownDeviceRepository,
    PgSessionRepository, PgUserRepository,
};
use crate::devices::repository::{
    PgApprovalRequestRepository, PgDeviceApprovalPolicyRepository, PgTrustedDeviceRepository,
};
use crate::directory_sync::repository::PgDirectorySyncConfigRepository;
use crate::emergency_access::repository::{
    PgEmergencyAccessPolicyRepository, PgEmergencyAccessRepository, PgEmergencyAccessRequestRepository,
};
use crate::eventos::{self, EmisorDeEventos};
use crate::export::repository::{PgExportPolicyRepository, PgExportRepository};
use crate::external_shares::repository::{PgExternalSharePolicyRepository, PgExternalShareRepository};
use crate::folders::repository::{PgFolderItemRepository, PgFolderRepository};
use crate::groups::repository::{PgGroupMemberRepository, PgGroupRepository, PgOrganizationRepository};
use crate::me::repository::PgPreferenciasRepository;
use crate::metadata::repository::{PgMetadataKeyEnvelopeRepository, PgMetadataKeyRepository};
use crate::mfa::repository::{PgMfaChallengeRepository, PgMfaPolicyRepository, PgTotpCredentialRepository};
use crate::notificaciones::PgOutboundEmailRepository;
use crate::passkeys::repository::{PgCeremonyStateRepository, PgPasskeyRepository};
use crate::password_policy::repository::PgPasswordPolicyRepository;
use crate::reports::repository::PgReportsRepository;
use crate::resources::repository::{
    PgPermissionRepository, PgResourceRepository, PgResourceTypeRepository,
    PgSecretEnvelopeRepository,
};
use crate::retention::repository::{PgPurgeRepository, PgRetentionPolicyRepository};
use crate::scim::repository::{PgScimTokenRepository, PgScimUserRepository};
use crate::smtp_config::repository::PgSmtpConfigRepository;
use crate::sso::repository::{PgLoginStateRepository, PgSsoConfigRepository, PgSsoIdentityRepository};
use crate::tags::repository::PgTagRepository;
use crate::users_admin::repository::PgUserPurgeRepository;
use ellkan_crypto::secretos::ClaveSecreta32;

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
    pub audit_log: PgAuditLogRepository,
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
    pub mfa_policy: PgMfaPolicyRepository,
    pub mfa_totp: PgTotpCredentialRepository,
    pub mfa_challenges: PgMfaChallengeRepository,
    pub smtp_config: PgSmtpConfigRepository,
    /// F-14: clave maestra de servidor para cifrar el secreto TOTP de login
    /// en reposo — nunca una clave del usuario. `Arc` (no `Clone` sobre el
    /// `SecretBox` en sí) para que `AppState` siga siendo barato de clonar
    /// por request, igual criterio que `server_public_key_ed25519`.
    pub secrets_key: Arc<ClaveSecreta32>,
    /// Rate limiting dedicado sobre `POST /auth/mfa/verify`, keyed por
    /// sesión parcial — más estricto que el general por usuario, porque un
    /// código TOTP de 6 dígitos tiene espacio de búsqueda acotado (F-14).
    pub limitador_mfa: Arc<DefaultKeyedRateLimiter<Uuid>>,
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
    // F-15
    pub password_policy: PgPasswordPolicyRepository,
    pub reportes: PgReportsRepository,
    // F-16 (account recovery, admin-driven)
    pub account_recovery_policy: PgAccountRecoveryPolicyRepository,
    pub org_recovery_key: PgOrgRecoveryKeyRepository,
    pub account_recovery_escrow: PgEscrowRepository,
    pub account_recovery_requests: PgRecoveryRequestRepository,
    // F-17
    pub sso_config: PgSsoConfigRepository,
    pub sso_identities: PgSsoIdentityRepository,
    pub sso_login_state: PgLoginStateRepository,
    // F-18
    pub scim_tokens: PgScimTokenRepository,
    pub scim_users: PgScimUserRepository,
    // F-19
    pub directory_sync_config: PgDirectorySyncConfigRepository,
    // F-36 (emergency access, peer-to-peer)
    pub emergency_access_policy: PgEmergencyAccessPolicyRepository,
    pub emergency_access: PgEmergencyAccessRepository,
    pub emergency_access_requests: PgEmergencyAccessRequestRepository,
    // F-40
    pub retention_policy: PgRetentionPolicyRepository,
    pub purge: PgPurgeRepository,
    pub users_purge: PgUserPurgeRepository,
    // F-30/F-31/F-39
    pub preferencias_usuario: PgPreferenciasRepository,
    // F-26
    pub external_shares: PgExternalShareRepository,
    pub external_share_policy: PgExternalSharePolicyRepository,
    // F-27/F-29
    pub export_policy: PgExportPolicyRepository,
    pub export_datos: PgExportRepository,
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
    pub fn nuevo(pool: sqlx::PgPool, server_public_key_ed25519: [u8; 32], secrets_key: ClaveSecreta32) -> Self {
        let cuota = Quota::per_second(NonZeroU32::new(10).expect("10 no es cero"))
            .allow_burst(NonZeroU32::new(20).expect("20 no es cero"));
        // F-14: "más estricto que el general" — 5 intentos por minuto por
        // sesión parcial, muy por debajo del espacio de búsqueda de un
        // código de 6 dígitos incluso sin la ventana de ±1 paso de TOTP.
        let cuota_mfa = Quota::per_minute(NonZeroU32::new(5).expect("5 no es cero"));
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
            audit_log: PgAuditLogRepository { pool: pool.clone() },
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
            mfa_policy: PgMfaPolicyRepository { pool: pool.clone() },
            mfa_totp: PgTotpCredentialRepository { pool: pool.clone() },
            mfa_challenges: PgMfaChallengeRepository { pool: pool.clone() },
            smtp_config: PgSmtpConfigRepository { pool: pool.clone() },
            secrets_key: Arc::new(secrets_key),
            limitador_mfa: Arc::new(governor::RateLimiter::keyed(cuota_mfa)),
            webauthn: Arc::new(construir_webauthn()),
            server_public_key_ed25519: Arc::new(server_public_key_ed25519),
            limitador_por_usuario: Arc::new(governor::RateLimiter::keyed(cuota)),
            password_policy: PgPasswordPolicyRepository { pool: pool.clone() },
            reportes: PgReportsRepository { pool: pool.clone() },
            account_recovery_policy: PgAccountRecoveryPolicyRepository { pool: pool.clone() },
            org_recovery_key: PgOrgRecoveryKeyRepository { pool: pool.clone() },
            account_recovery_escrow: PgEscrowRepository { pool: pool.clone() },
            account_recovery_requests: PgRecoveryRequestRepository { pool: pool.clone() },
            sso_config: PgSsoConfigRepository { pool: pool.clone() },
            sso_identities: PgSsoIdentityRepository { pool: pool.clone() },
            sso_login_state: PgLoginStateRepository { pool: pool.clone() },
            scim_tokens: PgScimTokenRepository { pool: pool.clone() },
            scim_users: PgScimUserRepository { pool: pool.clone() },
            directory_sync_config: PgDirectorySyncConfigRepository { pool: pool.clone() },
            emergency_access_policy: PgEmergencyAccessPolicyRepository { pool: pool.clone() },
            emergency_access: PgEmergencyAccessRepository { pool: pool.clone() },
            emergency_access_requests: PgEmergencyAccessRequestRepository { pool: pool.clone() },
            retention_policy: PgRetentionPolicyRepository { pool: pool.clone() },
            purge: PgPurgeRepository { pool: pool.clone() },
            users_purge: PgUserPurgeRepository { pool: pool.clone() },
            preferencias_usuario: PgPreferenciasRepository { pool: pool.clone() },
            external_shares: PgExternalShareRepository { pool: pool.clone() },
            external_share_policy: PgExternalSharePolicyRepository { pool: pool.clone() },
            export_policy: PgExportPolicyRepository { pool: pool.clone() },
            export_datos: PgExportRepository { pool: pool.clone() },
            pool,
        }
    }
}
