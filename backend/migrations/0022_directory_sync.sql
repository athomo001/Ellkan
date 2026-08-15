-- Autor: Athan Espinoza

-- F-19: Directory Sync LDAP. `bind_password_encrypted` cifrado con la clave
-- maestra de servidor (`secrets_key`, mismo criterio que F-14/F-16) — el
-- servidor necesita poder usarla él mismo para conectarse al directorio.

create table directory_sync_config (
    organization_id integer primary key references organizations(id),
    ldap_url text,
    bind_dn text,
    bind_password_encrypted bytea,
    bind_password_nonce bytea,
    -- TLS/StartTLS obligatorio (F-19) — `ldap://` plano sólo se acepta si
    -- `require_starttls = true`, nunca sin cifrado alguno.
    require_starttls boolean not null default false,
    base_dn text,
    -- Filtro adicional del admin, AND-eado con el filtro base de usuarios
    -- — se escapa (RFC 4515) antes de concatenar, nunca se interpola crudo.
    user_filter text,
    -- Mapeo de atributos LDAP -> campos de usuario. `userPassword` y
    -- equivalentes quedan excluidos duro en el código (F-19, "ni el propio
    -- admin la puede saltear"), no como default desactivable acá.
    attribute_mapping jsonb not null default
        '{"external_id": "uid", "email": "mail", "display_name": "cn"}',
    last_sync_at timestamptz,
    last_sync_dry_run_result jsonb
);

insert into directory_sync_config (organization_id) values (1);

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
    'password_policy.updated',
    'account_recovery.enrolled',
    'account_recovery.requested',
    'account_recovery.approved',
    'account_recovery.completed',
    'account_recovery_policy.updated',
    'emergency_access.designated',
    'emergency_access.accepted',
    'emergency_access.revoked',
    'emergency_access.requested',
    'emergency_access.approved',
    'emergency_access.rejected',
    'emergency_access.granted_by_timeout',
    'emergency_access_policy.updated',
    'retention_policy.updated',
    'retention.purge_ran',
    'user.purged',
    'user.deactivated',
    'user.activated',
    'sso.login_succeeded',
    'sso.account_linked',
    'sso.link_rejected_unverified_email',
    'sso.jit_provisioned',
    'sso_config.updated',
    'scim.user_created',
    'scim.user_updated',
    'scim.user_deactivated',
    'scim_token.created',
    'scim_token.revoked',
    'directory_sync.config_updated',
    'directory_sync.dry_run',
    'directory_sync.applied'
));
