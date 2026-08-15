-- Autor: Athan Espinoza

-- F-14/F-34: políticas de MFA a nivel organización, con vínculo criptográfico
-- MFA↔sesión (hash, nunca el ID en claro) y el secreto TOTP de login
-- server-verified — distinto del TOTP local de F-38 (nunca toca el servidor)
-- y del TOTP embebido de F-08 (contenido cifrado end-to-end, el servidor
-- nunca lo ve). Este secreto sí necesita vivir en el servidor para poder
-- verificarlo, así que se cifra en reposo con una clave maestra de servidor
-- nueva (no con una clave del usuario) — primera vez que Ellkan cifra algo
-- con una clave que el propio servidor controla.

create table mfa_policy (
    organization_id integer primary key references organizations(id),
    require_mfa boolean not null default false,
    -- Sólo 'totp' tiene un verificador real implementado hoy — 'webauthn'
    -- queda declarado en el modelo de datos (columna array abierta) pero
    -- rechazado explícitamente al guardar la política hasta que exista un
    -- segundo factor WebAuthn real en `POST /auth/mfa/verify`.
    allowed_methods text[] not null default '{totp}',
    grace_period_days integer not null default 7,
    -- Momento en que `require_mfa` pasó de `false` a `true` — determina
    -- desde cuándo corre `grace_period_days` para un usuario ya existente
    -- sin MFA configurado. `null` mientras la política nunca se activó.
    require_mfa_since timestamptz
);

insert into mfa_policy (organization_id) values (1);

create table user_totp_credentials (
    id uuid primary key default uuidv7(),
    user_id uuid not null references users(id),
    secret_ciphertext bytea not null,
    secret_nonce bytea not null,
    -- El setup exige confirmar un código antes de quedar activo — evita que
    -- un secreto generado pero nunca confirmado (ej. el usuario cerró la
    -- pantalla del QR sin escanearlo) bloquee logins futuros con un secreto
    -- que ninguna app autenticadora tiene todavía.
    confirmed_at timestamptz,
    created_at timestamptz not null default now(),
    deleted_at timestamptz
);

-- Un solo credential TOTP activo por usuario a la vez — deshabilitar y
-- volver a configurar es soft-delete + fila nueva, mismo criterio que el
-- resto del esquema.
create unique index user_totp_credentials_user_id_activo_idx
    on user_totp_credentials(user_id) where deleted_at is null;

create table mfa_challenges (
    id uuid primary key default uuidv7(),
    user_id uuid not null references users(id),
    method text not null check (method in ('totp')),
    -- SHA-256 de `sessions.id` de la sesión parcial que originó el desafío,
    -- nunca el ID en claro (F-34) — comparado en tiempo constante en Rust,
    -- nunca vía igualdad de SQL (mismo criterio que `device_challenges.code_hash`).
    session_hash bytea not null,
    expires_at timestamptz not null,
    consumed_at timestamptz
);

create index mfa_challenges_user_id_idx on mfa_challenges(user_id);

-- F-13: nuevos eventos auditables de esta fase — el catálogo cerrado de
-- `event_type` crece con cada checkbox de 1.3, mismo criterio documentado
-- en `0013_audit_log.sql`.
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
    'mfa_policy.updated'
));
