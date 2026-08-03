-- Autor: Athan Espinoza

-- Fase 0.2: esquema mínimo de "identidad y auth" + "recursos y cifrado". El
-- resto de las tablas (organización de recursos, seguridad organizacional,
-- external share) llegan en Fase 1 — no se crean acá para no adelantar
-- checkboxes de otra fase.

-- Postgres 18 trae uuidv7() nativo (ordenable por tiempo, mejor para índices
-- que uuidv4).

create table users (
    id uuid primary key default uuidv7(),
    email text not null unique,
    display_name text not null,
    active boolean not null default true,
    locale text not null default 'es' check (locale in ('en', 'es')),
    theme text not null default 'dark' check (theme in ('light', 'dark')),
    clipboard_clear_minutes integer not null default 1,
    auto_lock_minutes integer default 15,
    security_stamp uuid not null default gen_random_uuid(),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    deleted_at timestamptz
);

-- user_keys: `encrypted_private_key_blob` guarda los dos privados (X25519 +
-- Ed25519, 32+32 bytes) concatenados, cifrados como un solo blob. Nunca
-- cifrado con el output de Argon2id directo — siempre pasa por HKDF antes.
create table user_keys (
    id uuid primary key default uuidv7(),
    user_id uuid not null unique references users(id),
    public_key_x25519 bytea not null,
    public_key_ed25519 bytea not null,
    encrypted_private_key_blob bytea not null,
    private_key_nonce bytea not null,
    kdf_salt bytea not null,
    kdf_params jsonb not null default '{"m_cost_kib": 19456, "t_cost": 2, "p_cost": 1}',
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create table auth_challenges (
    id uuid primary key default uuidv7(),
    user_id uuid not null references users(id),
    nonce bytea not null,
    expires_at timestamptz not null,
    consumed_at timestamptz
);

create index auth_challenges_user_id_idx on auth_challenges(user_id);

create table sessions (
    id uuid primary key default uuidv7(),
    user_id uuid not null references users(id),
    security_stamp uuid not null,
    mfa_verified_at timestamptz,
    created_at timestamptz not null default now(),
    expires_at timestamptz not null,
    revoked_at timestamptz
);

create index sessions_user_id_idx on sessions(user_id);

create table known_devices (
    id uuid primary key default uuidv7(),
    user_id uuid not null references users(id),
    device_token_hash bytea not null,
    label text,
    first_seen_at timestamptz not null default now(),
    last_seen_at timestamptz not null default now(),
    unique (user_id, device_token_hash)
);

create table resource_types (
    id uuid primary key default uuidv7(),
    slug text not null unique,
    json_schema jsonb not null,
    deleted_at timestamptz
);

-- resource_type mínimo de Fase 0 (login/password genérico) — el catálogo
-- completo de F-07 llega en Fase 1.
insert into resource_types (slug, json_schema) values (
    'login-password',
    '{"metadata": ["name", "username", "uri"], "secret": ["password", "notes"]}'
);

-- metadata_ciphertext se cifra con la misma DEK por-recurso que sella
-- secret_envelopes.sealed_dek — Fase 0 no tiene metadata_keys compartida
-- todavía (eso es Fase 1.1, F-06 "metadata key compartida + TOFU").
create table resources (
    id uuid primary key default uuidv7(),
    resource_type_id uuid not null references resource_types(id),
    metadata_ciphertext bytea not null,
    metadata_nonce bytea not null,
    metadata_key_type text not null default 'user_key' check (metadata_key_type in ('user_key', 'shared_key')),
    created_by uuid not null references users(id),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    deleted_at timestamptz
);

create index resources_created_by_idx on resources(created_by);

-- Una fila por (resource_id, user_id) — revocar acceso = borrar la fila,
-- no requiere re-cifrar nada de otros usuarios.
create table secret_envelopes (
    id uuid primary key default uuidv7(),
    resource_id uuid not null references resources(id),
    user_id uuid not null references users(id),
    sealed_dek bytea not null,
    secret_ciphertext bytea not null,
    secret_nonce bytea not null,
    created_at timestamptz not null default now(),
    unique (resource_id, user_id)
);

create index secret_envelopes_user_id_idx on secret_envelopes(user_id);

create table permissions (
    id uuid primary key default uuidv7(),
    subject_type text not null check (subject_type in ('resource', 'folder')),
    subject_id uuid not null,
    grantee_type text not null check (grantee_type in ('user', 'group')),
    grantee_id uuid not null,
    level text not null check (level in ('read', 'update', 'owner')),
    created_at timestamptz not null default now(),
    unique (subject_type, subject_id, grantee_type, grantee_id)
);

create index permissions_subject_idx on permissions(subject_type, subject_id);
create index permissions_grantee_idx on permissions(grantee_type, grantee_id);
