-- Autor: Athan Espinoza

-- Identidad Ed25519 propia del servidor, para GET /auth/server-key
-- (verificación/pinning opcional a nivel de aplicación, independiente de
-- TLS). Fila única, generada al primer arranque si no existe (ver
-- backend/src/main.rs). No es un secreto zero-knowledge del usuario: es la
-- identidad del propio servidor, análoga a una clave TLS.
create table server_keys (
    id smallint primary key default 1 check (id = 1),
    public_key_ed25519 bytea not null,
    private_key_ed25519 bytea not null,
    created_at timestamptz not null default now()
);
