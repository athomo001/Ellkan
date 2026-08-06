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
    AuthLogout,
    /// F-14: código MFA incorrecto o desafío no encontrado — análogo a
    /// `AuthLoginFailed` pero para el segundo factor.
    AuthMfaFailed,
    PermissionGranted,
    GroupMemberAdded,
    GroupMemberRemoved,
    GroupManagerChanged,
    ResourceCreated,
    DeviceTrusted,
    DeviceRevoked,
    DeviceApprovalGranted,
    MetadataKeyCreated,
    MetadataKeyRotationStarted,
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
    AccountRecoveryCompleted,
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
}

impl AuditEventType {
    pub fn as_db_str(self) -> &'static str {
        match self {
            AuditEventType::AuthLoginSucceeded => "auth.login_succeeded",
            AuditEventType::AuthLoginFailed => "auth.login_failed",
            AuditEventType::AuthDeviceUnrecognized => "auth.device_unrecognized",
            AuditEventType::AuthDeviceVerified => "auth.device_verified",
            AuditEventType::AuthDeviceVerificationFailed => "auth.device_verification_failed",
            AuditEventType::AuthLogout => "auth.logout",
            AuditEventType::AuthMfaFailed => "auth.mfa_failed",
            AuditEventType::PermissionGranted => "permission.granted",
            AuditEventType::GroupMemberAdded => "group.member_added",
            AuditEventType::GroupMemberRemoved => "group.member_removed",
            AuditEventType::GroupManagerChanged => "group.manager_changed",
            AuditEventType::ResourceCreated => "resource.created",
            AuditEventType::DeviceTrusted => "device.trusted",
            AuditEventType::DeviceRevoked => "device.revoked",
            AuditEventType::DeviceApprovalGranted => "device.approval_granted",
            AuditEventType::MetadataKeyCreated => "metadata_key.created",
            AuditEventType::MetadataKeyRotationStarted => "metadata_key.rotation_started",
            AuditEventType::RoleCreated => "role.created",
            AuditEventType::RolePermissionsUpdated => "role.permissions_updated",
            AuditEventType::DeviceApprovalPolicyUpdated => "device_approval_policy.updated",
            AuditEventType::MfaEnrolled => "mfa.enrolled",
            AuditEventType::MfaPolicyUpdated => "mfa_policy.updated",
            AuditEventType::AccountRecoveryPolicyUpdated => "account_recovery_policy.updated",
            AuditEventType::AccountRecoveryEnrolled => "account_recovery.enrolled",
            AuditEventType::AccountRecoveryRequested => "account_recovery.requested",
            AuditEventType::AccountRecoveryApproved => "account_recovery.approved",
            AuditEventType::AccountRecoveryCompleted => "account_recovery.completed",
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
            "auth.logout" => AuditEventType::AuthLogout,
            "auth.mfa_failed" => AuditEventType::AuthMfaFailed,
            "permission.granted" => AuditEventType::PermissionGranted,
            "group.member_added" => AuditEventType::GroupMemberAdded,
            "group.member_removed" => AuditEventType::GroupMemberRemoved,
            "group.manager_changed" => AuditEventType::GroupManagerChanged,
            "resource.created" => AuditEventType::ResourceCreated,
            "device.trusted" => AuditEventType::DeviceTrusted,
            "device.revoked" => AuditEventType::DeviceRevoked,
            "device.approval_granted" => AuditEventType::DeviceApprovalGranted,
            "metadata_key.created" => AuditEventType::MetadataKeyCreated,
            "metadata_key.rotation_started" => AuditEventType::MetadataKeyRotationStarted,
            "role.created" => AuditEventType::RoleCreated,
            "role.permissions_updated" => AuditEventType::RolePermissionsUpdated,
            "device_approval_policy.updated" => AuditEventType::DeviceApprovalPolicyUpdated,
            "mfa.enrolled" => AuditEventType::MfaEnrolled,
            "mfa_policy.updated" => AuditEventType::MfaPolicyUpdated,
            "account_recovery_policy.updated" => AuditEventType::AccountRecoveryPolicyUpdated,
            "account_recovery.enrolled" => AuditEventType::AccountRecoveryEnrolled,
            "account_recovery.requested" => AuditEventType::AccountRecoveryRequested,
            "account_recovery.approved" => AuditEventType::AccountRecoveryApproved,
            "account_recovery.completed" => AuditEventType::AccountRecoveryCompleted,
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
