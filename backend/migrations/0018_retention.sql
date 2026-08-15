-- Autor: Athan Espinoza

-- F-40: política de retención y purga. `data_retention_days` rige el hard-delete
-- físico de filas soft-deleted (`deleted_at`) en tablas de dominio;
-- `audit_log_entries` queda explícitamente excluido de ese mecanismo — tiene
-- su propia retención (`audit_log_retention_days`), independiente y más
-- larga por defecto (compliance, no ciclo operativo normal).

alter table organizations add column data_retention_days integer not null default 90;
alter table organizations add column audit_log_retention_days integer not null default 365;

-- F-40 necesita poder purgar `audit_log_entries` vencidas según
-- `audit_log_retention_days`, pero el trigger de F-13
-- (`0013_audit_log.sql`) bloqueaba *todo* DELETE incondicionalmente —
-- correcto para "nadie puede borrar una entrada a mano", pero le pega
-- también al propio job de retención sancionado. Se reemplaza la función
-- del trigger (mismo trigger, misma tabla) para que seguir bloqueando
-- UPDATE siempre, y DELETE sólo cuando la fila todavía no venció su propia
-- retención — la política queda impuesta por la base, no por confiar en que
-- el único código que ejecuta el DELETE sea el job correcto: un bug futuro
-- que intente borrar una entrada reciente sigue rechazado al mismo nivel
-- que antes.
create or replace function audit_log_entries_bloquear_mutacion() returns trigger as $$
declare
    retencion_dias integer;
begin
    if tg_op = 'DELETE' then
        select audit_log_retention_days into retencion_dias from organizations where id = 1;
        if old.created_at > now() - (retencion_dias || ' days')::interval then
            raise exception 'audit_log_entries es append-only: DELETE no está permitido antes de audit_log_retention_days (% días)', retencion_dias;
        end if;
        return old;
    end if;
    raise exception 'audit_log_entries es append-only: % no está permitido', tg_op;
end;
$$ language plpgsql;

alter table audit_log_entries drop constraint audit_log_entries_event_type_check;
alter table audit_log_entries add constraint audit_log_entries_event_type_check check (event_type in (
    'auth.login_succeeded',
    'auth.login_failed',
    'auth.device_unrecognized',
    'auth.device_verified',
    'auth.device_verification_failed',
    'auth.logout',
    'auth.mfa_failed',
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
    'device_approval_policy.updated',
    'mfa.enrolled',
    'mfa_policy.updated',
    'password_policy.updated',
    'account_recovery.enrolled',
    'account_recovery.requested',
    'account_recovery.approved',
    'account_recovery.completed',
    'account_recovery_policy.updated',
    'emergency_access.designated',
    'emergency_access.accepted',
    'emergency_access.revoked',
    'emergency_access.requested',
    'emergency_access.approved',
    'emergency_access.rejected',
    'emergency_access.granted_by_timeout',
    'emergency_access_policy.updated',
    'retention_policy.updated',
    'retention.purge_ran'
));
