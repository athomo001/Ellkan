-- Autor: Athan Espinoza

-- F-12: grupos jerárquicos con managers por-grupo y subgrupos delegables.
-- `organizations` tampoco existía todavía — se crea acá con la fila única
-- de v1 (sin multi-tenant), sólo con la columna que este módulo necesita
-- (`max_group_depth`); el resto de columnas de la tabla llega cuando 1.3
-- las necesite, no todas de una.
create table organizations (
    id integer primary key default 1 check (id = 1),
    max_group_depth integer not null default 4
);

insert into organizations (id) values (1);

create table groups (
    id uuid primary key default uuidv7(),
    name text not null,
    parent_group_id uuid references groups(id),
    deleted_at timestamptz
);

-- Nombre único entre hermanos (mismo padre) — dos índices parciales porque
-- un `unique(parent_group_id, name)` plano no alcanza: Postgres trata cada
-- NULL como distinto entre sí, así que dos grupos raíz (`parent_group_id`
-- NULL) podrían repetir nombre sin que ese unique lo note.
create unique index groups_raiz_nombre_unico on groups(name)
    where parent_group_id is null and deleted_at is null;
create unique index groups_hijo_nombre_unico on groups(parent_group_id, name)
    where parent_group_id is not null and deleted_at is null;

create index groups_parent_group_id_idx on groups(parent_group_id);

create table group_members (
    group_id uuid not null references groups(id),
    user_id uuid not null references users(id),
    is_admin boolean not null default false,
    created_at timestamptz not null default now(),
    primary key (group_id, user_id)
);

create index group_members_user_id_idx on group_members(user_id);
