-- Autor: Athan Espinoza

-- F-16: Account Recovery con escrow opt-in. `org_recovery_keys` guarda el
-- ÚNICO keypair X25519 de recuperación organizacional — la privada cifrada
-- en reposo con la clave maestra de servidor (mismo `secrets_key` de F-14,
-- no una clave del usuario: el servidor necesita poder desellar el escrow
-- una vez que una solicitud junta el umbral de aprobaciones). La pública se
-- sirve a los clientes para que sellen su clave privada al enrolarse — el
-- pinning de fingerprint contra un re-sellado silencioso es responsabilidad
-- del cliente (F-16, informado por el paper de ETH Zurich/USENIX 2026).
create table org_recovery_keys (
    id integer primary key default 1 check (id = 1),
    public_key_x25519 bytea not null,
    encrypted_private_key bytea not null,
    private_key_nonce bytea not null,
    created_at timestamptz not null default now()
);

create table account_recovery_policy (
    organization_id integer primary key references organizations(id),
    required boolean not null default false,
    grace_period_days integer not null default 30,
    default_approval_threshold integer not null default 1
);

insert into account_recovery_policy (organization_id) values (1);

-- 1:1 con users — un usuario sólo puede tener un escrow activo a la vez.
create table account_recovery_escrow (
    id uuid primary key default uuidv7(),
    user_id uuid not null unique references users(id),
    sealed_private_key_for_org bytea not null,
    org_recovery_key_id integer not null references org_recovery_keys(id),
    approval_threshold integer not null,
    created_at timestamptz not null default now()
);

create table account_recovery_requests (
    id uuid primary key default uuidv7(),
    escrow_id uuid not null references account_recovery_escrow(id),
    requested_by uuid references users(id),
    status text not null default 'pending' check (status in ('pending', 'approved', 'rejected', 'completed')),
    -- Lista de {admin_id, approved_at} — un array y no un contador porque
    -- `approval_threshold` puede exigir más de un admin, y hace falta poder
    -- auditar *quién* aprobó, no sólo cuántos (F-16).
    approvals jsonb not null default '[]',
    -- Clave pública X25519 efímera que el cliente que recupera genera para
    -- esta solicitud puntual — la clave privada del usuario se re-sella
    -- contra ésta recién al alcanzar el umbral, nunca viaja en claro.
    requester_public_key_x25519 bytea not null,
    sealed_private_key_for_requester bytea,
    created_at timestamptz not null default now(),
    resolved_at timestamptz
);

create index account_recovery_requests_escrow_idx on account_recovery_requests(escrow_id);

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
    'account_recovery_policy.updated'
));
