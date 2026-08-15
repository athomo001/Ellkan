-- Autor: Athan Espinoza

-- F-18: SCIM 2.0. `scim_tokens` guarda sólo el hash del bearer token
-- (mismo criterio que `device_challenges.code_hash`) — una fuga de la base
-- no alcanza para suplantar al directorio externo. `users.external_id`
-- identifica el recurso SCIM de forma estable (RFC 7644): un reintento del
-- mismo `POST` con el mismo `externalId` nunca crea un duplicado.

create table scim_tokens (
    id uuid primary key default uuidv7(),
    organization_id integer not null references organizations(id),
    token_hash bytea not null,
    created_at timestamptz not null default now(),
    revoked_at timestamptz
);

alter table users add column external_id text;
create unique index users_external_id_idx on users(external_id) where external_id is not null and deleted_at is null;

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
    'scim_token.revoked'
));
