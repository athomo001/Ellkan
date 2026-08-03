-- Autor: Athan Espinoza

-- Groundwork mínimo de F-22 (RBAC configurable), adelantado sobre su fase
-- formal (1.3) porque Fase 1.1 ya depende de un concepto real de "admin de
-- organización" para tags compartidos (F-10) y grupos raíz (F-12). El panel
-- completo de administración de roles (F-20) sigue siendo Fase 1.4 — acá sólo
-- se sienta la tabla y el chequeo mínimo que ese panel va a exponer.

-- `role_permissions.permission` es un catálogo abierto (sin `check`), a
-- diferencia de `permissions.level`: los permisos administrativos van a
-- crecer en Fase 1.3 (mfa_policy.manage, audit_log.read, etc.) sin que cada
-- uno requiera una migración de schema nueva, sólo una fila.
create table roles (
    id uuid primary key default uuidv7(),
    name text not null unique,
    created_at timestamptz not null default now()
);

create table role_permissions (
    role_id uuid not null references roles(id) on delete cascade,
    permission text not null,
    primary key (role_id, permission)
);

insert into roles (name) values ('admin'), ('user'), ('auditor');

-- "*" es el comodín de superusuario — único permiso real que el código
-- consume hoy (extractor `AdminUser`); el resto queda sembrado como ejemplo
-- de rol custom pedido explícitamente por F-22 ("auditor"), sin consumidor
-- real todavía (F-13, auditoría, llega en Fase 1.3).
insert into role_permissions (role_id, permission)
select id, '*' from roles where name = 'admin';
insert into role_permissions (role_id, permission)
select id, 'audit_log.read' from roles where name = 'auditor';

-- Sin `default` a nivel de columna (Postgres no admite una subquery ahí,
-- y hardcodear el UUID generado por `uuidv7()` en la migración sería frágil)
-- — el rol `user` se resuelve explícitamente en `UserRepository::crear`.
alter table users add column role_id uuid references roles(id);
update users set role_id = (select id from roles where name = 'user');
alter table users alter column role_id set not null;
