-- Autor: Athan Espinoza

-- F-24: auto-registro con allowlist de dominios + verificación de email por
-- código antes de poder loguear.

-- Backfill obligatorio: sin esto, todo usuario ya existente (incluidos los
-- de instancias en producción) queda bloqueado de loguear en cuanto se
-- agrega el filtro `email_verified_at is not null` al choke point de login
-- (`buscar_por_email`/`buscar_por_id`/`SessionRepository::validar*`).
alter table users add column email_verified_at timestamptz;
update users set email_verified_at = coalesce(created_at, now());

-- Mismo shape que `device_challenges` (0003_verify_device.sql): código de
-- un solo uso hasheado, nunca en claro; TTL de 24h (vive en el email del
-- usuario, no en una sesión activa) — comparación en tiempo constante la
-- hace el Service, no esta tabla.
-- `on delete cascade`: mismo criterio que `0019_purge_usuario.sql` aplicó
-- retroactivamente a toda tabla con `user_id` — sin esto, purgar un usuario
-- (F-40) con un desafío de verificación pendiente falla por violación de
-- foreign key en vez de completar la purga.
create table email_verification_challenges (
    id uuid primary key default uuidv7(),
    user_id uuid not null references users(id) on delete cascade,
    code_hash bytea not null,
    expires_at timestamptz not null,
    consumed_at timestamptz
);
create index email_verification_challenges_user_id_idx on email_verification_challenges(user_id);

create table self_registration_policy (
    organization_id integer primary key references organizations(id),
    enabled boolean not null default true,
    -- Vacío = sin restricción de dominio (cualquier email). No vacío =
    -- allowlist estricta, comparación case-insensitive contra la parte
    -- después de '@'.
    allowed_domains text[] not null default '{}'
);
insert into self_registration_policy (organization_id) values (1);

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
    'smtp_config.updated',
    'user.passphrase_changed',
    'self_registration_policy.updated',
    'user.email_verified'
));
