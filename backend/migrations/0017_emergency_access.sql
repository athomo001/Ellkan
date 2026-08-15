-- Autor: Athan Espinoza

-- F-36: Emergency Access peer-to-peer. `sealed_material` viaja ya sellado
-- client-side contra la clave pública X25519 del contacto elegido (mismo
-- criterio que compartir un recurso, F-11/F-05) — el servidor nunca sella
-- ni desella acá, sólo autoriza cuándo el contacto puede leer esos bytes
-- opacos: tras aprobación explícita del titular, o al vencer el plazo sin
-- respuesta (job programado).

alter table organizations add column emergency_access_enabled boolean not null default true;

create table emergency_access (
    id uuid primary key default uuidv7(),
    granter_id uuid not null references users(id),
    grantee_id uuid not null references users(id),
    access_level text not null check (access_level in ('view', 'takeover')),
    sealed_material bytea not null,
    wait_time_days integer not null default 7,
    status text not null default 'invited' check (status in ('invited', 'accepted', 'confirmed')),
    created_at timestamptz not null default now()
);

create index emergency_access_granter_idx on emergency_access(granter_id);
create index emergency_access_grantee_idx on emergency_access(grantee_id);

create table emergency_access_requests (
    id uuid primary key default uuidv7(),
    emergency_access_id uuid not null references emergency_access(id),
    requested_at timestamptz not null default now(),
    status text not null default 'pending' check (status in ('pending', 'approved', 'rejected', 'granted_by_timeout')),
    resolved_at timestamptz
);

-- Sólo una solicitud pendiente a la vez por contacto de emergencia — evita
-- que el contacto spamee solicitudes duplicadas mientras una ya está en
-- curso.
create unique index emergency_access_requests_pendiente_unica_idx
    on emergency_access_requests(emergency_access_id) where status = 'pending';

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
    'emergency_access_policy.updated'
));
