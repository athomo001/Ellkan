-- Autor: Athan Espinoza

-- Revocación remota (docs/revocacion-remota.md): al bloquear o purgar una
-- cuenta, el servidor manda a las apps de escritorio vinculadas un aviso
-- FIRMADO con su clave Ed25519 para que borren la bóveda local.
--
-- `cuentas_revocadas`: para una cuenta PURGADA ya no hay fila en `users`, así
-- que una app que estaba sin red no tendría contra qué preguntar. Se guarda
-- sólo la clave pública Ed25519 de la cuenta y su id (un UUID, sin datos
-- personales: ni correo ni nombre), compatible con el derecho al olvido de
-- F-40. Con eso `POST /auth/estado-cuenta` le puede responder a quien
-- demuestre ser dueño de esa clave. Se borra pasada la retención del log de
-- auditoría (`retention::job`). Una cuenta bloqueada no necesita fila acá: su
-- fila de `users` sigue existiendo.
create table cuentas_revocadas (
    public_key_ed25519 bytea primary key,
    user_id uuid not null,
    revocada_en timestamptz not null default now()
);
create index cuentas_revocadas_user_id_idx on cuentas_revocadas (user_id);

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
    'scim.token_revoked',
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
    'group.share_exempt_changed',
    'resource.ownership_transferred',
    'user.remote_wipe_signaled'
));
