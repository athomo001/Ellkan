-- Autor: Athan Espinoza

-- F-06 completo: metadata key compartida (hasta 2 activas a la vez, F-33) +
-- la mitad privada envuelta por destinatario autorizado.
create table metadata_keys (
    id uuid primary key default uuidv7(),
    public_key_x25519 bytea not null,
    fingerprint text not null,
    expired_at timestamptz,
    deleted_at timestamptz
);

create table metadata_key_envelopes (
    id uuid primary key default uuidv7(),
    metadata_key_id uuid not null references metadata_keys(id),
    user_id uuid references users(id),
    sealed_private_key bytea not null,
    unique (metadata_key_id, user_id)
);

-- Pendiente desde `0005_folders.sql`: `metadata_keys` recién existe ahora.
alter table folders
    add constraint folders_name_key_id_fkey foreign key (name_key_id) references metadata_keys(id);

-- `metadata_key_type` ya existía desde `0001_fase0_core.sql`
-- (`user_key`/`shared_key`, default `user_key`) — sólo faltaba la FK real a
-- la clave compartida en sí.
alter table resources add column metadata_key_id uuid references metadata_keys(id);
