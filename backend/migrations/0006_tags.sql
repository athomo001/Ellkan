-- Autor: Athan Espinoza

-- F-10: tags personales (`is_shared=false`, default) y compartidos.
create table tags (
    id uuid primary key default uuidv7(),
    name text not null,
    is_shared boolean not null default false,
    created_by uuid not null references users(id),
    deleted_at timestamptz
);

create index tags_created_by_idx on tags(created_by);

create table resource_tags (
    resource_id uuid not null references resources(id),
    tag_id uuid not null references tags(id),
    primary key (resource_id, tag_id)
);

create index resource_tags_tag_id_idx on resource_tags(tag_id);
