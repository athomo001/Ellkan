-- Autor: Athan Espinoza

-- Hallazgo real de uso (2026-08-13): la visibilidad de compartir acotada
-- por grupo (0037) es correcta pero total — no hay forma de que un grupo
-- "de soporte técnico" (TI y similares, que crean cuentas/comparten
-- contraseñas para OTRAS áreas por norma) comparta hacia cualquiera sin
-- que el admin de organización tenga que involucrarse en cada caso. El
-- admin puede: (a) marcar grupos puntuales como exentos (sus miembros ven
-- y comparten con cualquiera, igual que vería un admin de organización,
-- pero sin ningún otro privilegio de admin), o (b) apagar la restricción
-- entera y volver al comportamiento "cualquiera ve a cualquiera" de antes
-- de 0037.

alter table groups add column share_exempt boolean not null default false;

create table sharing_policy (
    organization_id integer primary key references organizations(id),
    restrict_visibility_by_group boolean not null default true
);
insert into sharing_policy (organization_id) values (1);

alter table audit_log_entries drop constraint audit_log_entries_event_type_check;
alter table audit_log_entries add constraint audit_log_entries_event_type_check check (event_type in (
    'auth.login_succeeded',
    'auth.login_failed',
    'auth.device_unrecognized',
    'auth.device_verified',
    'auth.device_verification_failed',
    'auth.device_auto_verified_no_smtp',
    'auth.logout',
    'auth.mfa_failed',
    'permission.granted',
    'group.member_added',
    'group.member_removed',
    'group.manager_changed',
    'resource.created',
    'device.trusted',
    'device.revoked',
    'device.approval_granted',
    'metadata_key.created',
    'metadata_key.rotation_started',
    'metadata_key.member_added',
    'role.created',
    'role.permissions_updated',
    'device_approval_policy.updated',
    'mfa.enrolled',
    'mfa_policy.updated',
    'account_recovery_policy.updated',
    'account_recovery.enrolled',
    'account_recovery.requested',
    'account_recovery.approved',
    'account_recovery.rejected',
    'account_recovery.completed',
    'password_policy.updated',
    'retention_policy.updated',
    'retention.purge_ran',
    'emergency_access.designated',
    'emergency_access.requested',
    'emergency_access.approved',
    'emergency_access.rejected',
    'emergency_access.accepted',
    'emergency_access.revoked',
    'emergency_access.granted_by_timeout',
    'emergency_access_policy.updated',
    'user.deactivated',
    'user.activated',
    'user.purged',
    'sso.config_updated',
    'sso.login_succeeded',
    'sso.jit_provisioned',
    'sso.account_linked',
    'sso.link_rejected_unverified_email',
    'scim.token_created',
    'scim.user_created',
    'scim.user_updated',
    'scim.user_deactivated',
    'directory_sync.config_updated',
    'directory_sync.dry_run',
    'directory_sync.applied',
    'external_share.created',
    'external_share.accessed',
    'external_share.revoked',
    'external_share.burned',
    'external_share_policy.updated',
    'export_policy.updated',
    'export.performed',
    'import.performed',
    'users.exported',
    'groups.exported',
    'backup.created',
    'backup.failed',
    'backup.restored',
    'restore.failed',
    'cli.cleanup_ran',
    'cli.user_promoted',
    'cli.recovery_setup_issued',
    'passkey.revoked',
    'resource.updated',
    'smtp_config.updated',
    'user.passphrase_changed',
    'self_registration_policy.updated',
    'user.email_verified',
    'resource.deleted',
    'recovery_kit.generated',
    'recovery_kit.reset_requested',
    'recovery_kit.reset_completed',
    'recovery_kit.reset_mfa_failed',
    'sharing_policy.updated',
    'group.share_exempt_changed'
));
