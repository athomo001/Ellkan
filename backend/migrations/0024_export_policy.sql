-- Autor: Athan Espinoza

-- F-27: política organizacional de exportación/importación personal —
-- tres controles independientes, editables en runtime desde el admin
-- (a diferencia de Passbolt CE, donde `ExportPolicies` sólo lee de
-- env/archivo). Único caso de v1.6 con tabla propia: F-28 (backup) y F-29
-- (export masivo) son deliberadamente sin tabla, ver
-- `spec/02-modelo-de-datos.md` §5bis.
create table export_policy (
    organization_id integer primary key references organizations(id),
    export_enabled boolean not null default true,
    -- Passbolt CE hoy: CSV apagado, KDBX sin gate alguno — mismo default acá.
    allowed_formats text[] not null default '{kdbx}',
    import_enabled boolean not null default true
);

insert into export_policy (organization_id) values (1);

-- Fase 1.6 completa: eventos de F-27 (política, export/import reportado por
-- el cliente), F-29 (export masivo de usuarios/grupos) y F-28/F-41
-- restantes (CLI-only, sin sesión HTTP — `actor_user_id` queda NULL salvo
-- en `cli.user_promoted`/`cli.recovery_setup_issued`, donde el sujeto es
-- el usuario afectado, no el operador que corrió el comando).
alter table audit_log_entries drop constraint audit_log_entries_event_type_check;
alter table audit_log_entries add constraint audit_log_entries_event_type_check check (event_type in (
    'auth.login_succeeded',
    'auth.login_failed',
    'auth.device_unrecognized',
    'auth.device_verified',
    'auth.device_verification_failed',
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
    'role.created',
    'role.permissions_updated',
    'device_approval_policy.updated',
    'mfa.enrolled',
    'mfa_policy.updated',
    'account_recovery_policy.updated',
    'account_recovery.enrolled',
    'account_recovery.requested',
    'account_recovery.approved',
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
    'cli.recovery_setup_issued'
));
