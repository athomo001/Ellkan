-- Autor: Athan Espinoza

-- Modo escritorio (spec/13 §4/§5): dialecto SQLite de folders/folder_items/
-- tags/resource_tags — se crea directo en su forma FINAL (Postgres llegó acá
-- via 0005_folders.sql + 0006_tags.sql + 0031_folder_permissions.sql: el
-- nombre cifrado de una carpeta es por-usuario y vive en `folder_items`,
-- `folders` sólo guarda el id compartido entre todas las vistas). Sin
-- `permissions` (spec/13 §5, no se porta) — compartir una carpeta con otro
-- usuario/grupo no aplica en este modo, sólo organizar la propia bóveda.
create table folders (
    id text primary key,
    deleted_at text
);

-- `folder_id` = posición (padre) de un ítem en el árbol de `user_id`,
-- nullable a propósito (raíz). Cada ítem es una carpeta (`child_folder_id`
-- + nombre sellado) o un recurso (`resource_id`, sin nombre propio acá — su
-- metadata ya vive cifrada en `resources`), nunca ambos.
create table folder_items (
    id text primary key,
    folder_id text references folders(id),
    resource_id text references resources(id),
    child_folder_id text references folders(id),
    user_id text not null,
    name_ciphertext blob,
    name_nonce blob,
    created_at text not null default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    check (
        (resource_id is not null and child_folder_id is null and name_ciphertext is null and name_nonce is null) or
        (resource_id is null and child_folder_id is not null and name_ciphertext is not null and name_nonce is not null)
    ),
    unique (user_id, resource_id),
    unique (user_id, child_folder_id)
);
create index folder_items_user_id_idx on folder_items(user_id);
create index folder_items_folder_id_idx on folder_items(folder_id);

-- F-10: tags personales (`is_shared=0`, default) y compartidos — en modo
-- escritorio `is_shared` nunca se usa en 1 (spec/13 §5), la columna se
-- mantiene por consistencia con el modelo de datos, no por necesidad real.
create table tags (
    id text primary key,
    name text not null,
    is_shared integer not null default 0,
    created_by text not null,
    deleted_at text
);
create index tags_created_by_idx on tags(created_by);

create table resource_tags (
    resource_id text not null references resources(id),
    tag_id text not null references tags(id),
    primary key (resource_id, tag_id)
);
create index resource_tags_tag_id_idx on resource_tags(tag_id);
