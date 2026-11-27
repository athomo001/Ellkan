-- Autor: Athan Espinoza
--
-- ELK-03 (#149): igual que la migración 0067 del servidor. Fallos
-- consecutivos del segundo factor por cuenta y el bloqueo temporal que derivan.

create table mfa_failed_attempts (
    user_id text primary key,
    failed_count integer not null default 0,
    locked_until text,
    last_failed_at text not null default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
