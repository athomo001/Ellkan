-- Autor: Athan Espinoza

-- F-47 (sync, spec/13 §7): sincronizar carpetas/tags exige poder responder
-- "¿qué cambió desde el cursor X?" — `folder_items`/`tags` nunca tuvieron
-- ninguna columna de timestamp para eso (sólo `folder_items.created_at`,
-- que no captura un `reposicionar`/`insertar_carpeta` posterior). Se agrega
-- `updated_at`, tocada explícitamente por la capa de aplicación en cada
-- escritura (mismo criterio que `resources.updated_at` — sin trigger de
-- Postgres, la app ya sigue ese patrón en todo el resto del schema).
alter table folder_items add column updated_at timestamptz not null default now();
alter table tags add column updated_at timestamptz not null default now();
