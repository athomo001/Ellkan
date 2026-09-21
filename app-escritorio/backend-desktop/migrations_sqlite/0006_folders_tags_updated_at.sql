-- Autor: Athan Espinoza

-- Modo escritorio: mismo motivo que la migración Postgres equivalente
-- (0047_folders_tags_updated_at.sql) — F-47 (sync) necesita "¿qué cambió
-- desde el cursor X?" sobre `folder_items`/`tags`, que hoy sólo tienen
-- `created_at`/nada. Tocada explícitamente por la app en cada escritura,
-- mismo criterio que `resources.updated_at` en este mismo esquema.
alter table folder_items add column updated_at text not null default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
alter table tags add column updated_at text not null default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
