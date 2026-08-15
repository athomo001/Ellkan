-- Autor: Athan Espinoza

-- F-15: políticas de password/passphrase organizacionales. La validación de
-- entropía en sí (zxcvbn) corre client-side — el servidor nunca ve la
-- passphrase en claro para poder validarla — así que esta tabla sólo
-- almacena los parámetros que el cliente lee para aplicar la regla, más las
-- reglas del generador de contraseñas de recursos.

create table password_policy (
    organization_id integer primary key references organizations(id),
    min_passphrase_length integer not null default 12,
    min_passphrase_entropy_bits integer not null default 60,
    -- null = sin rotación forzada (default, siguiendo NIST SP 800-63B).
    passphrase_rotation_days integer,
    generator_default_length integer not null default 20,
    generator_charset_rules jsonb not null default
        '{"uppercase": true, "lowercase": true, "digits": true, "symbols": true, "exclude_ambiguous": true}',
    -- Techos opcionales sobre lo que cada usuario configura en `users`
    -- (F-39) — null = sin techo.
    max_clipboard_clear_minutes integer,
    max_auto_lock_minutes integer
);

insert into password_policy (organization_id) values (1);

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
    'password_policy.updated'
));
