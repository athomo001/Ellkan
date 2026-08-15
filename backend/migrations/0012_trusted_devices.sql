-- Autor: Athan Espinoza

-- F-37: Trusted Device / Login with Device. El servidor nunca sella ni
-- desella nada acá — sólo mueve bytes opacos entre dispositivos, mismo
-- criterio que `metadata_key_envelopes`.
create table trusted_devices (
    id uuid primary key default uuidv7(),
    user_id uuid not null references users(id),
    device_public_key bytea not null,
    -- Nullable a propósito: revocar "borra sealed_user_private_key" (F-37
    -- literal) — la fila persiste (queda el registro de que existió, con
    -- `revoked_at`), pero el blob que permite desenvolver la clave privada
    -- desaparece de verdad, no queda como bytes vacíos disfrazados.
    sealed_user_private_key bytea,
    label text,
    created_at timestamptz not null default now(),
    revoked_at timestamptz
);

create index trusted_devices_user_id_idx on trusted_devices(user_id);

-- Solicitud de aprobación de un dispositivo nuevo, sin sesión todavía.
-- `session_id`/`sealed_user_private_key` quedan null hasta que un
-- dispositivo confiable aprueba — recién ahí el dispositivo nuevo puede
-- completar su login localmente.
create table device_approval_requests (
    id uuid primary key default uuidv7(),
    user_id uuid not null references users(id),
    device_public_key bytea not null,
    fingerprint text not null,
    status text not null default 'pending' check (status in ('pending', 'approved', 'rejected', 'expired')),
    sealed_user_private_key bytea,
    session_id uuid references sessions(id),
    created_at timestamptz not null default now(),
    expires_at timestamptz not null
);

create index device_approval_requests_user_id_idx on device_approval_requests(user_id);

-- F-20/F-37: política organizacional de qué alternativas de aprobación
-- están habilitadas. `allow_admin_device_approval` default `false` porque
-- su mecanismo real depende de que exista escrow de Account Recovery
-- (F-16, Fase 1.3) — el toggle ya queda listo, pero apagado, hasta que
-- ese mecanismo exista de verdad.
alter table organizations add column allow_peer_device_approval boolean not null default true;
alter table organizations add column allow_admin_device_approval boolean not null default false;
