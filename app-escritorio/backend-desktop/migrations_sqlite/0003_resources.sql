-- Autor: Athan Espinoza

-- Modo escritorio (spec/13 §4/§5): dialecto SQLite de resource_types/
-- resources/secret_envelopes (Postgres: 0001_fase0_core.sql). Sin
-- `permissions`/`groups`/`folders`/`roles` — ese esquema no se porta
-- (spec/13 §5, se compilan afuera). `resources.metadata_key_type` queda fijo
-- en 'user_key' en la práctica (invariante de modo local, spec/13 §5) pero
-- se mantiene la columna para no reabrir el modelo si algún día se necesita.
create table resource_types (
    id text primary key,
    slug text not null unique,
    json_schema text not null,
    deleted_at text
);

insert into resource_types (id, slug, json_schema) values (
    '019a0000-0000-7000-8000-000000000001',
    'login-password',
    '{"metadata": ["name", "username", "uri"], "secret": ["password", "notes"]}'
);

create table resources (
    id text primary key,
    resource_type_id text not null,
    metadata_ciphertext blob not null,
    metadata_nonce blob not null,
    metadata_key_type text not null default 'user_key',
    metadata_key_id text,
    created_by text not null,
    created_at text not null default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at text not null default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    deleted_at text
);
create index resources_created_by_idx on resources(created_by);

-- Una fila por (resource_id, user_id) — en modo local siempre 1 sola (spec/13
-- §5: "secret_envelopes -> siempre 1 fila por recurso, sellada para uno
-- mismo"), el mecanismo de varias filas por destinatario no se toca.
create table secret_envelopes (
    id text primary key,
    resource_id text not null,
    user_id text not null,
    sealed_dek blob not null,
    secret_ciphertext blob not null,
    secret_nonce blob not null,
    created_at text not null default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    unique (resource_id, user_id)
);
create index secret_envelopes_user_id_idx on secret_envelopes(user_id);
