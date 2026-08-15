-- Autor: Athan Espinoza

-- F-17: SSO OIDC. `sso_login_state` es el equivalente de
-- `webauthn_ceremony_state` (F-03) para el ciclo redirect->callback: server
-- side, indexado por el propio `state` opaco de un solo uso — nunca en una
-- cookie/sesión de cliente, porque el callback es una navegación de tope
-- (top-level) sin contexto de sesión previo.

create table sso_config (
    organization_id integer primary key references organizations(id),
    provider text not null default 'oidc' check (provider in ('oidc')),
    issuer_url text,
    client_id text,
    -- F-17: JIT provisioning apagado por default — sin cuenta local
    -- preexistente, un login SSO no crea una cuenta nueva salvo que el
    -- admin lo habilite explícitamente.
    jit_provisioning_enabled boolean not null default false
);

insert into sso_config (organization_id) values (1);

create table sso_identities (
    id uuid primary key default uuidv7(),
    user_id uuid not null references users(id) on delete cascade,
    provider text not null check (provider in ('oidc', 'saml')),
    provider_user_id text not null,
    provider_metadata jsonb not null default '{}',
    created_at timestamptz not null default now(),
    unique (provider, provider_user_id)
);

create table sso_login_state (
    state text primary key,
    nonce text not null,
    pkce_verifier text not null,
    expires_at timestamptz not null,
    consumed_at timestamptz
);

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
    'sso_config.updated'
));
