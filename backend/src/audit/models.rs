// Autor: Athan Espinoza

use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

/// Catálogo cerrado de eventos auditables (F-13) — crece a medida que el
/// resto de 1.3 agregue nuevas acciones, nunca texto libre en el código que
/// las emite. `as_db_str`/`from_db_str` son la única frontera de
/// serialización, igual criterio que `NivelPermiso` en `resources::models`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEventType {
    AuthLoginSucceeded,
    AuthLoginFailed,
    AuthDeviceUnrecognized,
    AuthDeviceVerified,
    AuthDeviceVerificationFailed,
    /// F-02/Parte B (SMTP editable): SMTP no está configurado, así que el
    /// dispositivo se marca conocido sin pedir código — nunca queda
    /// silencioso, esto es lo que permite auditar cuántos logins pasaron
    /// sin la verificación real.
    AuthDeviceAutoVerifiedNoSmtp,
    AuthLogout,
    /// F-14: código MFA incorrecto o desafío no encontrado — análogo a
    /// `AuthLoginFailed` pero para el segundo factor.
    AuthMfaFailed,
    PermissionGranted,
    GroupMemberAdded,
    GroupMemberRemoved,
    GroupManagerChanged,
    ResourceCreated,
    /// F-07: edición de un recurso ya creado — nunca contiene metadata/secreto,
    /// sólo cuántos destinatarios se re-sellaron.
    ResourceUpdated,
    /// 2026-08-11: borrado real de un recurso (`DELETE /resources/{id}`,
    /// antes no existía). Restringido a admin de grupo (si vive en una
    /// carpeta de grupo) o admin de organización.
    ResourceDeleted,
    DeviceTrusted,
    DeviceRevoked,
    DeviceApprovalGranted,
    /// F-03 (PRF): revocación de una passkey propia (`DELETE /me/passkeys/{id}`).
    PasskeyRevoked,
    MetadataKeyCreated,
    MetadataKeyRotationStarted,
    /// Módulo "compartir de verdad" (spec/11 + hallazgo real de uso
    /// 2026-08-10): un admin agrega un miembro nuevo a una metadata key
    /// compartida ya existente, sin rotarla.
    MetadataKeyMemberAdded,
    RoleCreated,
    RolePermissionsUpdated,
    DeviceApprovalPolicyUpdated,
    /// F-14: primer código TOTP confirmado con éxito (alta o reemplazo).
    MfaEnrolled,
    MfaPolicyUpdated,
    AccountRecoveryPolicyUpdated,
    AccountRecoveryEnrolled,
    AccountRecoveryRequested,
    AccountRecoveryApproved,
    /// 2026-08-11: F-16 gana rechazar, delegado a admin de grupo igual que
    /// aprobar — antes no existía ningún camino de código para esto.
    AccountRecoveryRejected,
    AccountRecoveryCompleted,
    /// Recovery kit (self-held, sin escrow de admin — módulo nuevo, distinto
    /// de F-16): `PUT /me/recovery-kit`.
    RecoveryKitGenerated,
    RecoveryKitResetRequested,
    RecoveryKitResetCompleted,
    RecoveryKitResetMfaFailed,
    PasswordPolicyUpdated,
    RetentionPolicyUpdated,
    RetentionPurgeRan,
    EmergencyAccessDesignated,
    EmergencyAccessRequested,
    EmergencyAccessApproved,
    EmergencyAccessRejected,
    EmergencyAccessAccepted,
    EmergencyAccessRevoked,
    EmergencyAccessGrantedByTimeout,
    EmergencyAccessPolicyUpdated,
    UserDeactivated,
    UserActivated,
    UserPurged,
    SsoConfigUpdated,
    SsoLoginSucceeded,
    SsoJitProvisioned,
    SsoAccountLinked,
    SsoLinkRejectedUnverifiedEmail,
    ScimTokenCreated,
    ScimUserCreated,
    ScimUserUpdated,
    ScimUserDeactivated,
    DirectorySyncConfigUpdated,
    DirectorySyncDryRun,
    DirectorySyncApplied,
    /// F-26: creación de un external share (`POST /external-shares`).
    ExternalShareCreated,
    /// F-26: acceso exitoso al contenido (`GET /external-shares/{id}` sin
    /// autenticación) — nunca se audita el contenido en sí, sólo el evento.
    ExternalShareAccessed,
    ExternalShareRevoked,
    /// F-26: se alcanzó `max_views` o venció `expires_at` — en ambos casos
    /// dispara el borrado efectivo de `ciphertext`, no sólo un flag.
    ExternalShareBurned,
    ExternalSharePolicyUpdated,
    /// F-27
    ExportPolicyUpdated,
    /// F-27: reportado por el cliente vía `POST /export-events` — nunca
    /// transmite contenido, sólo formato/cantidad.
    ExportPerformed,
    ImportPerformed,
    /// F-29
    UsersExported,
    GroupsExported,
    /// F-28/F-41: CLI-only, sin sesión HTTP — `actor_user_id` va `None`
    /// salvo en los dos eventos que sí tienen un usuario afectado como
    /// sujeto (`CliUserPromoted`/`CliRecoverySetupIssued`).
    BackupCreated,
    BackupFailed,
    BackupRestored,
    RestoreFailed,
    CliCleanupRan,
    CliUserPromoted,
    CliRecoverySetupIssued,
    /// Parte A (SMTP editable): host/puerto/from/tls/usuario/contraseña
    /// cambiados desde `PUT /admin/smtp-config` — nunca incluye la
    /// contraseña en sí en `metadata`.
    SmtpConfigUpdated,
    /// F-01: `POST /me/change-passphrase` — nunca contiene la passphrase ni
    /// la clave privada en `metadata`, sólo el hecho de que ocurrió.
    PassphraseChanged,
    /// F-24: `PUT /admin/self-registration-policy`.
    SelfRegistrationPolicyUpdated,
    /// F-24: código de verificación de email confirmado — habilita el
    /// login de una cuenta recién auto-registrada.
    EmailVerified,
    /// 2026-08-13: `PUT /admin/sharing-policy`.
    SharingPolicyUpdated,
    /// 2026-08-13: `PUT /groups/{id}/share-exempt`.
    GroupShareExemptChanged,
}

impl AuditEventType {
    pub fn as_db_str(self) -> &'static str {
        match self {
            AuditEventType::AuthLoginSucceeded => "auth.login_succeeded",
            AuditEventType::AuthLoginFailed => "auth.login_failed",
            AuditEventType::AuthDeviceUnrecognized => "auth.device_unrecognized",
            AuditEventType::AuthDeviceVerified => "auth.device_verified",
            AuditEventType::AuthDeviceVerificationFailed => "auth.device_verification_failed",
            AuditEventType::AuthDeviceAutoVerifiedNoSmtp => "auth.device_auto_verified_no_smtp",
            AuditEventType::AuthLogout => "auth.logout",
            AuditEventType::AuthMfaFailed => "auth.mfa_failed",
            AuditEventType::PermissionGranted => "permission.granted",
            AuditEventType::GroupMemberAdded => "group.member_added",
            AuditEventType::GroupMemberRemoved => "group.member_removed",
            AuditEventType::GroupManagerChanged => "group.manager_changed",
            AuditEventType::ResourceCreated => "resource.created",
            AuditEventType::ResourceUpdated => "resource.updated",
            AuditEventType::ResourceDeleted => "resource.deleted",
            AuditEventType::DeviceTrusted => "device.trusted",
            AuditEventType::DeviceRevoked => "device.revoked",
            AuditEventType::DeviceApprovalGranted => "device.approval_granted",
            AuditEventType::PasskeyRevoked => "passkey.revoked",
            AuditEventType::MetadataKeyCreated => "metadata_key.created",
            AuditEventType::MetadataKeyRotationStarted => "metadata_key.rotation_started",
            AuditEventType::MetadataKeyMemberAdded => "metadata_key.member_added",
            AuditEventType::RoleCreated => "role.created",
            AuditEventType::RolePermissionsUpdated => "role.permissions_updated",
            AuditEventType::DeviceApprovalPolicyUpdated => "device_approval_policy.updated",
            AuditEventType::MfaEnrolled => "mfa.enrolled",
            AuditEventType::MfaPolicyUpdated => "mfa_policy.updated",
            AuditEventType::AccountRecoveryPolicyUpdated => "account_recovery_policy.updated",
            AuditEventType::AccountRecoveryEnrolled => "account_recovery.enrolled",
            AuditEventType::AccountRecoveryRequested => "account_recovery.requested",
            AuditEventType::AccountRecoveryApproved => "account_recovery.approved",
            AuditEventType::AccountRecoveryRejected => "account_recovery.rejected",
            AuditEventType::AccountRecoveryCompleted => "account_recovery.completed",
            AuditEventType::RecoveryKitGenerated => "recovery_kit.generated",
            AuditEventType::RecoveryKitResetRequested => "recovery_kit.reset_requested",
            AuditEventType::RecoveryKitResetCompleted => "recovery_kit.reset_completed",
            AuditEventType::RecoveryKitResetMfaFailed => "recovery_kit.reset_mfa_failed",
            AuditEventType::PasswordPolicyUpdated => "password_policy.updated",
            AuditEventType::RetentionPolicyUpdated => "retention_policy.updated",
            AuditEventType::RetentionPurgeRan => "retention.purge_ran",
            AuditEventType::EmergencyAccessDesignated => "emergency_access.designated",
            AuditEventType::EmergencyAccessRequested => "emergency_access.requested",
            AuditEventType::EmergencyAccessApproved => "emergency_access.approved",
            AuditEventType::EmergencyAccessRejected => "emergency_access.rejected",
            AuditEventType::EmergencyAccessAccepted => "emergency_access.accepted",
            AuditEventType::EmergencyAccessRevoked => "emergency_access.revoked",
            AuditEventType::EmergencyAccessGrantedByTimeout => "emergency_access.granted_by_timeout",
            AuditEventType::EmergencyAccessPolicyUpdated => "emergency_access_policy.updated",
            AuditEventType::UserDeactivated => "user.deactivated",
            AuditEventType::UserActivated => "user.activated",
            AuditEventType::UserPurged => "user.purged",
            AuditEventType::SsoConfigUpdated => "sso.config_updated",
            AuditEventType::SsoLoginSucceeded => "sso.login_succeeded",
            AuditEventType::SsoJitProvisioned => "sso.jit_provisioned",
            AuditEventType::SsoAccountLinked => "sso.account_linked",
            AuditEventType::SsoLinkRejectedUnverifiedEmail => "sso.link_rejected_unverified_email",
            AuditEventType::ScimTokenCreated => "scim.token_created",
            AuditEventType::ScimUserCreated => "scim.user_created",
            AuditEventType::ScimUserUpdated => "scim.user_updated",
            AuditEventType::ScimUserDeactivated => "scim.user_deactivated",
            AuditEventType::DirectorySyncConfigUpdated => "directory_sync.config_updated",
            AuditEventType::DirectorySyncDryRun => "directory_sync.dry_run",
            AuditEventType::DirectorySyncApplied => "directory_sync.applied",
            AuditEventType::ExternalShareCreated => "external_share.created",
            AuditEventType::ExternalShareAccessed => "external_share.accessed",
            AuditEventType::ExternalShareRevoked => "external_share.revoked",
            AuditEventType::ExternalShareBurned => "external_share.burned",
            AuditEventType::ExternalSharePolicyUpdated => "external_share_policy.updated",
            AuditEventType::ExportPolicyUpdated => "export_policy.updated",
            AuditEventType::ExportPerformed => "export.performed",
            AuditEventType::ImportPerformed => "import.performed",
            AuditEventType::UsersExported => "users.exported",
            AuditEventType::GroupsExported => "groups.exported",
            AuditEventType::BackupCreated => "backup.created",
            AuditEventType::BackupFailed => "backup.failed",
            AuditEventType::BackupRestored => "backup.restored",
            AuditEventType::RestoreFailed => "restore.failed",
            AuditEventType::CliCleanupRan => "cli.cleanup_ran",
            AuditEventType::CliUserPromoted => "cli.user_promoted",
            AuditEventType::CliRecoverySetupIssued => "cli.recovery_setup_issued",
            AuditEventType::SmtpConfigUpdated => "smtp_config.updated",
            AuditEventType::PassphraseChanged => "user.passphrase_changed",
            AuditEventType::SelfRegistrationPolicyUpdated => "self_registration_policy.updated",
            AuditEventType::EmailVerified => "user.email_verified",
            AuditEventType::SharingPolicyUpdated => "sharing_policy.updated",
            AuditEventType::GroupShareExemptChanged => "group.share_exempt_changed",
        }
    }

    /// Usado por el filtro `?event_type=` de `GET /admin/audit-log` — un
    /// valor que no está en el catálogo es `INVALID_INPUT`, nunca se deja
    /// pasar como texto libre a la query.
    pub fn from_db_str(s: &str) -> Option<Self> {
        Some(match s {
            "auth.login_succeeded" => AuditEventType::AuthLoginSucceeded,
            "auth.login_failed" => AuditEventType::AuthLoginFailed,
            "auth.device_unrecognized" => AuditEventType::AuthDeviceUnrecognized,
            "auth.device_verified" => AuditEventType::AuthDeviceVerified,
            "auth.device_verification_failed" => AuditEventType::AuthDeviceVerificationFailed,
            "auth.device_auto_verified_no_smtp" => AuditEventType::AuthDeviceAutoVerifiedNoSmtp,
            "auth.logout" => AuditEventType::AuthLogout,
            "auth.mfa_failed" => AuditEventType::AuthMfaFailed,
            "permission.granted" => AuditEventType::PermissionGranted,
            "group.member_added" => AuditEventType::GroupMemberAdded,
            "group.member_removed" => AuditEventType::GroupMemberRemoved,
            "group.manager_changed" => AuditEventType::GroupManagerChanged,
            "resource.created" => AuditEventType::ResourceCreated,
            "resource.updated" => AuditEventType::ResourceUpdated,
            "resource.deleted" => AuditEventType::ResourceDeleted,
            "device.trusted" => AuditEventType::DeviceTrusted,
            "device.revoked" => AuditEventType::DeviceRevoked,
            "device.approval_granted" => AuditEventType::DeviceApprovalGranted,
            "passkey.revoked" => AuditEventType::PasskeyRevoked,
            "metadata_key.created" => AuditEventType::MetadataKeyCreated,
            "metadata_key.rotation_started" => AuditEventType::MetadataKeyRotationStarted,
            "metadata_key.member_added" => AuditEventType::MetadataKeyMemberAdded,
            "role.created" => AuditEventType::RoleCreated,
            "role.permissions_updated" => AuditEventType::RolePermissionsUpdated,
            "device_approval_policy.updated" => AuditEventType::DeviceApprovalPolicyUpdated,
            "mfa.enrolled" => AuditEventType::MfaEnrolled,
            "mfa_policy.updated" => AuditEventType::MfaPolicyUpdated,
            "account_recovery_policy.updated" => AuditEventType::AccountRecoveryPolicyUpdated,
            "account_recovery.enrolled" => AuditEventType::AccountRecoveryEnrolled,
            "account_recovery.requested" => AuditEventType::AccountRecoveryRequested,
            "account_recovery.approved" => AuditEventType::AccountRecoveryApproved,
            "account_recovery.rejected" => AuditEventType::AccountRecoveryRejected,
            "account_recovery.completed" => AuditEventType::AccountRecoveryCompleted,
            "recovery_kit.generated" => AuditEventType::RecoveryKitGenerated,
            "recovery_kit.reset_requested" => AuditEventType::RecoveryKitResetRequested,
            "recovery_kit.reset_completed" => AuditEventType::RecoveryKitResetCompleted,
            "recovery_kit.reset_mfa_failed" => AuditEventType::RecoveryKitResetMfaFailed,
            "password_policy.updated" => AuditEventType::PasswordPolicyUpdated,
            "retention_policy.updated" => AuditEventType::RetentionPolicyUpdated,
            "retention.purge_ran" => AuditEventType::RetentionPurgeRan,
            "emergency_access.designated" => AuditEventType::EmergencyAccessDesignated,
            "emergency_access.requested" => AuditEventType::EmergencyAccessRequested,
            "emergency_access.approved" => AuditEventType::EmergencyAccessApproved,
            "emergency_access.rejected" => AuditEventType::EmergencyAccessRejected,
            "emergency_access.accepted" => AuditEventType::EmergencyAccessAccepted,
            "emergency_access.revoked" => AuditEventType::EmergencyAccessRevoked,
            "emergency_access.granted_by_timeout" => AuditEventType::EmergencyAccessGrantedByTimeout,
            "emergency_access_policy.updated" => AuditEventType::EmergencyAccessPolicyUpdated,
            "user.deactivated" => AuditEventType::UserDeactivated,
            "user.activated" => AuditEventType::UserActivated,
            "user.purged" => AuditEventType::UserPurged,
            "sso.config_updated" => AuditEventType::SsoConfigUpdated,
            "sso.login_succeeded" => AuditEventType::SsoLoginSucceeded,
            "sso.jit_provisioned" => AuditEventType::SsoJitProvisioned,
            "sso.account_linked" => AuditEventType::SsoAccountLinked,
            "sso.link_rejected_unverified_email" => AuditEventType::SsoLinkRejectedUnverifiedEmail,
            "scim.token_created" => AuditEventType::ScimTokenCreated,
            "scim.user_created" => AuditEventType::ScimUserCreated,
            "scim.user_updated" => AuditEventType::ScimUserUpdated,
            "scim.user_deactivated" => AuditEventType::ScimUserDeactivated,
            "directory_sync.config_updated" => AuditEventType::DirectorySyncConfigUpdated,
            "directory_sync.dry_run" => AuditEventType::DirectorySyncDryRun,
            "directory_sync.applied" => AuditEventType::DirectorySyncApplied,
            "external_share.created" => AuditEventType::ExternalShareCreated,
            "external_share.accessed" => AuditEventType::ExternalShareAccessed,
            "external_share.revoked" => AuditEventType::ExternalShareRevoked,
            "external_share.burned" => AuditEventType::ExternalShareBurned,
            "external_share_policy.updated" => AuditEventType::ExternalSharePolicyUpdated,
            "export_policy.updated" => AuditEventType::ExportPolicyUpdated,
            "export.performed" => AuditEventType::ExportPerformed,
            "import.performed" => AuditEventType::ImportPerformed,
            "users.exported" => AuditEventType::UsersExported,
            "groups.exported" => AuditEventType::GroupsExported,
            "backup.created" => AuditEventType::BackupCreated,
            "backup.failed" => AuditEventType::BackupFailed,
            "backup.restored" => AuditEventType::BackupRestored,
            "restore.failed" => AuditEventType::RestoreFailed,
            "cli.cleanup_ran" => AuditEventType::CliCleanupRan,
            "cli.user_promoted" => AuditEventType::CliUserPromoted,
            "cli.recovery_setup_issued" => AuditEventType::CliRecoverySetupIssued,
            "smtp_config.updated" => AuditEventType::SmtpConfigUpdated,
            "user.passphrase_changed" => AuditEventType::PassphraseChanged,
            "self_registration_policy.updated" => AuditEventType::SelfRegistrationPolicyUpdated,
            "user.email_verified" => AuditEventType::EmailVerified,
            "sharing_policy.updated" => AuditEventType::SharingPolicyUpdated,
            "group.share_exempt_changed" => AuditEventType::GroupShareExemptChanged,
            _ => return None,
        })
    }
}

/// Payload que viaja por `DomainEvent::Auditoria` — nunca contiene
/// passphrase/secreto/contenido descifrado, sólo qué pasó y sobre qué
/// objeto (F-13, sección "qué nunca entra al log").
#[derive(Debug, Clone)]
pub struct EventoAuditoria {
    pub event_type: AuditEventType,
    /// `None` = acción no atribuible a un usuario existente (ej. intento de
    /// login con un email que no tiene cuenta — anti user-enumeration, el
    /// intento igual queda registrado internamente).
    pub actor_user_id: Option<Uuid>,
    pub subject_type: Option<&'static str>,
    pub subject_id: Option<Uuid>,
    pub metadata: Value,
}

impl EventoAuditoria {
    pub fn nuevo(event_type: AuditEventType, actor_user_id: Option<Uuid>) -> Self {
        Self { event_type, actor_user_id, subject_type: None, subject_id: None, metadata: Value::Null }
    }

    pub fn con_sujeto(mut self, subject_type: &'static str, subject_id: Uuid) -> Self {
        self.subject_type = Some(subject_type);
        self.subject_id = Some(subject_id);
        self
    }

    pub fn con_metadata(mut self, metadata: Value) -> Self {
        self.metadata = metadata;
        self
    }
}

/// Fila ya persistida — lo que devuelve `GET /admin/audit-log`.
#[derive(Debug, Clone)]
pub struct AuditLogEntry {
    pub id: Uuid,
    pub actor_user_id: Option<Uuid>,
    /// Email del actor al momento de leer el log — no se guarda una copia en
    /// `audit_log_entries` (se resuelve por join en cada lectura), así que
    /// puede quedar `None` si el usuario ya fue purgado del todo.
    pub actor_email: Option<String>,
    pub event_type: String,
    pub subject_type: Option<String>,
    pub subject_id: Option<Uuid>,
    pub metadata: Value,
    pub created_at: OffsetDateTime,
}

/// Filtros de `GET /admin/audit-log` — ya validados por el Controller antes
/// de llegar al Service (`event_type` ya resuelto contra el catálogo
/// cerrado).
#[derive(Debug, Clone, Default)]
pub struct FiltroAuditLog {
    pub actor_user_id: Option<Uuid>,
    pub event_type: Option<AuditEventType>,
    pub desde: Option<OffsetDateTime>,
    pub hasta: Option<OffsetDateTime>,
}
