-- Autor: Athan Espinoza

-- Modo escritorio (spec/13 §4): dialecto SQLite del mismo par de tablas que
-- backend/migrations/0038_recovery_kit.sql (Postgres). Diferencias de
-- dialecto, no de modelo: `uuid`/`bytea`/`timestamptz` no existen en SQLite
-- — ids y timestamps se guardan como TEXT (forma canónica con guiones para
-- ids, RFC 3339 para timestamps), `bytea` -> BLOB, `boolean` -> INTEGER
-- (0/1, sqlx lo mapea a `bool` de forma nativa). El id se genera en la capa
-- de aplicación (Rust, `Uuid::now_v7()`) antes del insert — sin equivalente
-- a `default uuidv7()` acá. Sin `references users(id)`: `users` todavía no
-- existe en este esquema recortado (sólo se migran los módulos de este
-- slice) y sqlx-sqlite activa `foreign_keys=ON` por defecto (a diferencia de
-- SQLite crudo, que lo trae apagado) — una FK a una tabla inexistente rompe
-- el `create table` en el momento, no recién al insertar. Se vuelve a
-- agregar cuando `auth`/`users` gane su propia migración SQLite.
create table recovery_kits (
    id text primary key,
    user_id text not null unique,
    kit_public_key_x25519 blob not null,
    sealed_identity_material blob not null,
    must_rotate integer not null default 0,
    created_at text not null default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at text not null default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

create table recovery_reset_tokens (
    id text primary key,
    user_id text not null,
    token_hash blob not null,
    expires_at text not null,
    consumed_at text,
    email_code_hash blob,
    email_code_expires_at text,
    created_at text not null default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
create index recovery_reset_tokens_user_id_idx on recovery_reset_tokens(user_id);
create index recovery_reset_tokens_token_hash_idx on recovery_reset_tokens(token_hash);
