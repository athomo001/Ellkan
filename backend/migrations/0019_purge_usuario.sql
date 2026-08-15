-- Autor: Athan Espinoza

-- F-40 (segundo checkbox): borrado atómico y selectivo de usuario. Todas
-- las FK hacia `users` eran `NO ACTION` (a propósito, en cada migración
-- anterior — un `DELETE` sin pensar no debía arrastrar nada por accidente).
-- Ahora que existe un flujo real y deliberado de borrado (`PurgeService`,
-- transacción explícita con dry-run obligatorio antes), se re-clasifican en
-- dos grupos:
--   - CASCADE: filas que son enteramente del propio usuario y no tienen
--     ningún sentido sin él (sesiones, credenciales, sus propios
--     `secret_envelopes`/`metadata_key_envelopes` — perder acceso a lo que
--     tenía es exactamente lo que F-40 pide, "pierde acceso a todo lo que
--     tenía", sin tocar las filas de nadie más).
--   - SET NULL: filas que sobreviven al usuario (un recurso que sigue
--     compartido con otros, una entrada de auditoría histórica) — pierden
--     la atribución, no la existencia.
-- `permissions.grantee_id` no tiene FK real (columna polimórfica
-- user/group) — el `PurgeService` borra esas filas explícitamente, la base
-- no puede hacerlo por él.

alter table user_keys drop constraint user_keys_user_id_fkey,
    add constraint user_keys_user_id_fkey foreign key (user_id) references users(id) on delete cascade;
alter table auth_challenges drop constraint auth_challenges_user_id_fkey,
    add constraint auth_challenges_user_id_fkey foreign key (user_id) references users(id) on delete cascade;
alter table sessions drop constraint sessions_user_id_fkey,
    add constraint sessions_user_id_fkey foreign key (user_id) references users(id) on delete cascade;
alter table known_devices drop constraint known_devices_user_id_fkey,
    add constraint known_devices_user_id_fkey foreign key (user_id) references users(id) on delete cascade;
alter table device_challenges drop constraint device_challenges_user_id_fkey,
    add constraint device_challenges_user_id_fkey foreign key (user_id) references users(id) on delete cascade;
alter table folder_items drop constraint folder_items_user_id_fkey,
    add constraint folder_items_user_id_fkey foreign key (user_id) references users(id) on delete cascade;
alter table group_members drop constraint group_members_user_id_fkey,
    add constraint group_members_user_id_fkey foreign key (user_id) references users(id) on delete cascade;
alter table secret_envelopes drop constraint secret_envelopes_user_id_fkey,
    add constraint secret_envelopes_user_id_fkey foreign key (user_id) references users(id) on delete cascade;
alter table metadata_key_envelopes drop constraint metadata_key_envelopes_user_id_fkey,
    add constraint metadata_key_envelopes_user_id_fkey foreign key (user_id) references users(id) on delete cascade;
alter table passkeys drop constraint passkeys_user_id_fkey,
    add constraint passkeys_user_id_fkey foreign key (user_id) references users(id) on delete cascade;
alter table webauthn_ceremony_state drop constraint webauthn_ceremony_state_user_id_fkey,
    add constraint webauthn_ceremony_state_user_id_fkey foreign key (user_id) references users(id) on delete cascade;
alter table trusted_devices drop constraint trusted_devices_user_id_fkey,
    add constraint trusted_devices_user_id_fkey foreign key (user_id) references users(id) on delete cascade;
alter table device_approval_requests drop constraint device_approval_requests_user_id_fkey,
    add constraint device_approval_requests_user_id_fkey foreign key (user_id) references users(id) on delete cascade;
alter table user_totp_credentials drop constraint user_totp_credentials_user_id_fkey,
    add constraint user_totp_credentials_user_id_fkey foreign key (user_id) references users(id) on delete cascade;
alter table mfa_challenges drop constraint mfa_challenges_user_id_fkey,
    add constraint mfa_challenges_user_id_fkey foreign key (user_id) references users(id) on delete cascade;
alter table account_recovery_escrow drop constraint account_recovery_escrow_user_id_fkey,
    add constraint account_recovery_escrow_user_id_fkey foreign key (user_id) references users(id) on delete cascade;
alter table emergency_access drop constraint emergency_access_granter_id_fkey,
    add constraint emergency_access_granter_id_fkey foreign key (granter_id) references users(id) on delete cascade;
alter table emergency_access drop constraint emergency_access_grantee_id_fkey,
    add constraint emergency_access_grantee_id_fkey foreign key (grantee_id) references users(id) on delete cascade;

alter table resources alter column created_by drop not null;
alter table resources drop constraint resources_created_by_fkey,
    add constraint resources_created_by_fkey foreign key (created_by) references users(id) on delete set null;
alter table tags alter column created_by drop not null;
alter table tags drop constraint tags_created_by_fkey,
    add constraint tags_created_by_fkey foreign key (created_by) references users(id) on delete set null;
alter table account_recovery_requests drop constraint account_recovery_requests_requested_by_fkey,
    add constraint account_recovery_requests_requested_by_fkey foreign key (requested_by) references users(id) on delete set null;

-- `ON DELETE SET NULL` sobre `audit_log_entries.actor_user_id` internamente
-- corre un UPDATE contra la fila — el trigger append-only de F-13
-- (`before update`) lo rechazaría igual que cualquier otro UPDATE. Se
-- agrega una excepción angosta: permite un UPDATE sólo si el único cambio
-- es poner `actor_user_id` a null (el resto de las columnas, byte a byte,
-- igual) — nunca un UPDATE que además toque `event_type`/`metadata`/etc.
alter table audit_log_entries drop constraint audit_log_entries_actor_user_id_fkey,
    add constraint audit_log_entries_actor_user_id_fkey foreign key (actor_user_id) references users(id) on delete set null;

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

    if tg_op = 'UPDATE'
        and new.actor_user_id is null and old.actor_user_id is not null
        and new.event_type = old.event_type
        and new.subject_type is not distinct from old.subject_type
        and new.subject_id is not distinct from old.subject_id
        and new.metadata = old.metadata
        and new.created_at = old.created_at
    then
        return new;
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
    'retention.purge_ran',
    'user.purged',
    'user.deactivated',
    'user.activated'
));
