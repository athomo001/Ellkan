-- Autor: Athan Espinoza

-- F-09: carpetas con vista por-usuario (equivalente a `folders_relations` de
-- Passbolt). `name_key_id` queda sin FK todavía — `metadata_keys` recién se
-- crea en la migración siguiente (F-06); se agrega esa constraint ahí.
create table folders (
    id uuid primary key default uuidv7(),
    name_ciphertext bytea not null,
    name_nonce bytea not null,
    name_key_id uuid,
    deleted_at timestamptz
);

-- `folder_id` es la posición (padre) de un ítem para un usuario puntual —
-- nullable a propósito, a diferencia de la descripción abreviada de
-- `02-modelo-de-datos.md` sección 4: sin esto no habría forma de representar
-- "esta carpeta está en la raíz del árbol de este usuario", que es
-- exactamente el caso más común. Mismo criterio que `folder_parent_id`
-- nullable en `folders_relations` de Passbolt, del que esta tabla es
-- equivalente directo.
create table folder_items (
    id uuid primary key default uuidv7(),
    folder_id uuid references folders(id),
    resource_id uuid references resources(id),
    child_folder_id uuid references folders(id),
    user_id uuid not null references users(id),
    created_at timestamptz not null default now(),
    check (
        (resource_id is not null and child_folder_id is null) or
        (resource_id is null and child_folder_id is not null)
    ),
    -- Un mismo ítem (recurso o sub-carpeta) tiene una única posición por
    -- usuario en un momento dado.
    unique (user_id, resource_id),
    unique (user_id, child_folder_id)
);

create index folder_items_user_id_idx on folder_items(user_id);
create index folder_items_folder_id_idx on folder_items(folder_id);
