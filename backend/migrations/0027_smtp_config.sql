-- Autor: Athan Espinoza

-- Reemplaza `ELLKAN_SMTP_*` (variables de entorno, leídas una sola vez al
-- arrancar el proceso) por una tabla real, editable desde el admin sin
-- reiniciar — decisión explícita del usuario: quiere SMTP configurable de
-- verdad desde la UI, no una pantalla de sólo lectura. Mismo patrón
-- singleton que `mfa_policy` (0014_mfa.sql). La contraseña se cifra en
-- reposo con la misma clave maestra de servidor que ya usa F-14 para el
-- secreto TOTP (`AppState.secrets_key`, AEAD) — nunca texto plano, aunque
-- viva en la base de datos.
create table smtp_config (
    organization_id integer primary key references organizations(id),
    host text,
    port integer,
    from_address text,
    -- Mismo criterio que `notificaciones::SmtpConfig` ya tenía por variable
    -- de entorno: `true` = STARTTLS + auth (relay real), `false` = relay
    -- local sin cifrar (Mailhog de dev/test) — nunca un default inseguro
    -- implícito, el admin lo tiene que tildar a propósito.
    tls boolean not null default true,
    username text,
    password_ciphertext bytea,
    password_nonce bytea,
    updated_at timestamptz not null default now()
);

insert into smtp_config (organization_id) values (1);

-- F-02/Parte B + Parte A: dos eventos nuevos — el bypass de verificación de
-- dispositivo cuando SMTP no está configurado, y el cambio de la config
-- SMTP en sí. Mismo patrón acumulativo que cada migración anterior que
-- extendió este catálogo, lista completa recopiada de
-- 0026_resource_updated_audit_event.sql más los dos valores nuevos.
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
    'cli.recovery_setup_issued',
    'passkey.revoked',
    'resource.updated',
    'smtp_config.updated'
));
