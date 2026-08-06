-- Autor: Athan Espinoza

-- F-13: registro inmutable de eventos de seguridad relevantes. Consumido de
-- forma asíncrona vía el mismo bus de domain events que ya usan
-- `notificaciones`/`metadata::rotacion` (`DomainEvent::Auditoria`) — nunca
-- dentro de la misma transacción que la acción auditada, así que una falla
-- al escribir el log nunca puede tumbar la operación real.
--
-- `event_type` es un catálogo cerrado (para que un SIEM externo pueda
-- filtrar por tipo de forma confiable) que crece con `alter table ... add
-- value`-equivalente (acá: reemplazar el check) a medida que el resto de
-- 1.3 agregue nuevas acciones auditables (MFA, políticas, account recovery,
-- SSO/SCIM) — mismo criterio ya usado para `permissions.level`/
-- `grantee_type`. Sólo se listan acá los eventos que ya tienen un
-- consumidor real en el código (auth, permisos/grupos, recursos
-- compartidos, dispositivos de confianza, metadata key, roles).
create table audit_log_entries (
    id uuid primary key default uuidv7(),
    actor_user_id uuid references users(id),
    event_type text not null check (event_type in (
        'auth.login_succeeded',
        'auth.login_failed',
        'auth.device_unrecognized',
        'auth.device_verified',
        'auth.device_verification_failed',
        'auth.logout',
        'permission.granted',
        'group.member_added',
        'group.member_removed',
        'group.manager_changed',
        'resource.created',
        'device.trusted',
        'device.revoked',
        'device.approval_granted',
        'metadata_key.created',
        'metadata_key.rotation_started',
        'role.created',
        'role.permissions_updated',
        'device_approval_policy.updated'
    )),
    subject_type text,
    subject_id uuid,
    metadata jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now()
);

-- Índices para los filtros de `GET /admin/audit-log` (actor/tipo/fecha) más
-- el orden de paginación por keyset (`id desc` alcanza: `uuidv7()` es
-- monótono con `created_at`, así que no hace falta un cursor compuesto).
create index audit_log_entries_actor_idx on audit_log_entries(actor_user_id);
create index audit_log_entries_event_type_idx on audit_log_entries(event_type);
create index audit_log_entries_created_at_idx on audit_log_entries(created_at);

-- Append-only reforzado en la base, no sólo por convención de código: sin
-- `updated_at`/`deleted_at`, y un trigger que rechaza cualquier UPDATE/DELETE
-- pase lo que pase en la capa de aplicación.
--
-- **Desviación documentada, no oculta**: el mecanismo que describe
-- `02-modelo-de-datos.md` es "revocar los grants de UPDATE/DELETE al rol de
-- aplicación" — pero hoy Ellkan corre con un único rol de Postgres que
-- además es el dueño del esquema (migra y sirve tráfico con la misma
-- credencial), y un `REVOKE` sobre una tabla no tiene efecto sobre su propio
-- dueño (los privilegios de owner no pasan por el sistema de ACL). Introducir
-- un segundo rol de aplicación sin privilegios de owner es un cambio de
-- infraestructura transversal a *todo* el esquema, no específico de esta
-- tabla — queda fuera del alcance de este checkbox. El trigger de acá cubre
-- el caso real que hoy puede pasar (un bug de aplicación que intente un
-- UPDATE/DELETE) con la misma garantía de "nadie reescribe la historia"
-- que pedía el diseño original, aunque no proteja contra un superusuario
-- ya comprometido — ese nivel adicional queda para cuando exista
-- separación real de roles de conexión.
create function audit_log_entries_bloquear_mutacion() returns trigger as $$
begin
    raise exception 'audit_log_entries es append-only: % no está permitido', tg_op;
end;
$$ language plpgsql;

create trigger audit_log_entries_sin_update
    before update on audit_log_entries
    for each row execute function audit_log_entries_bloquear_mutacion();

create trigger audit_log_entries_sin_delete
    before delete on audit_log_entries
    for each row execute function audit_log_entries_bloquear_mutacion();
