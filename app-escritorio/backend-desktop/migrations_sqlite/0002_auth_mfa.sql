-- Autor: Athan Espinoza

-- Modo escritorio (spec/13 §4/§5): dialecto SQLite de `users`/`user_keys`/
-- `auth_challenges`/`sessions`/`known_devices`/`device_challenges`/
-- `email_verification_challenges` (Postgres: 0001_fase0_core.sql y
-- siguientes) + `user_totp_credentials`/`mfa_challenges` (F-14, para F-38).
--
-- Recorte deliberado respecto del schema Postgres, mismo criterio que
-- 0001_recovery_kit.sql: sin `role_id` (el módulo de roles se compila
-- afuera en este modo, spec/13 §16 — "el rol es vestigial") ni ninguna
-- columna que sólo tenga sentido con grupos/organización (todo eso vive en
-- `roles`/`role_permissions`/`groups`, que no se portan). `mfa_policy` no
-- tiene tabla propia acá a propósito — no hay política organizacional que
-- administrar con 1 solo usuario, se resuelve fija en el repository
-- (ver `mfa/repository_sqlite.rs`).
create table users (
    id text primary key,
    email text not null unique,
    display_name text not null,
    security_stamp text not null,
    must_change_passphrase integer not null default 0,
    email_verified_at text,
    active integer not null default 1,
    deleted_at text,
    locale text not null default 'es',
    created_at text not null default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

create table user_keys (
    user_id text primary key,
    public_key_x25519 blob not null,
    public_key_ed25519 blob not null,
    encrypted_private_key_blob blob not null,
    private_key_nonce blob not null,
    kdf_salt blob not null
);

create table auth_challenges (
    id text primary key,
    user_id text not null,
    nonce blob not null,
    expires_at text not null,
    consumed_at text
);

create table sessions (
    id text primary key,
    user_id text not null,
    security_stamp text not null,
    mfa_verified_at text,
    expires_at text not null,
    revoked_at text
);

create table known_devices (
    user_id text not null,
    device_token_hash blob not null,
    mfa_verified_at text,
    last_seen_at text not null default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    primary key (user_id, device_token_hash)
);

create table device_challenges (
    id text primary key,
    user_id text not null,
    device_token_hash blob not null,
    code_hash blob not null,
    expires_at text not null,
    consumed_at text
);

create table email_verification_challenges (
    id text primary key,
    user_id text not null,
    code_hash blob not null,
    expires_at text not null,
    consumed_at text
);

-- F-14/F-38: credential TOTP de login, y sus desafíos pendientes.
create table user_totp_credentials (
    id text primary key,
    user_id text not null,
    secret_ciphertext blob not null,
    secret_nonce blob not null,
    confirmed_at text,
    ultimo_paso_aceptado integer,
    deleted_at text,
    created_at text not null default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

create table mfa_challenges (
    id text primary key,
    user_id text not null,
    method text not null,
    session_hash blob not null,
    code_hash blob,
    expires_at text not null,
    consumed_at text
);

-- Identidad Ed25519 propia del backend local (`GET /auth/server-key`) — igual
-- criterio que la versión Postgres (`cargar_o_generar_server_key`), generada
-- una sola vez y persistida para que no cambie en cada arranque.
create table server_keys (
    id integer primary key check (id = 1),
    public_key_ed25519 blob not null,
    private_key_ed25519 blob not null
);

-- Clave maestra local (F-14: cifra en reposo el secreto TOTP de login) — en
-- modo servidor la fija el operador vía `ELLKAN_SECRETS_KEY`; en modo
-- escritorio no hay operador, así que se genera una sola vez (CSPRNG) y se
-- persiste acá, mismo criterio que `server_keys`.
create table desktop_secrets (
    id integer primary key check (id = 1),
    secrets_key blob not null
);
