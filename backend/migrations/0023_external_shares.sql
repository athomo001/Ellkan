-- Autor: Athan Espinoza

-- F-26: External Secure Share. `id` usa `gen_random_uuid()` (v4, alta
-- entropía) **a propósito, nunca `uuidv7()`** — el resto del schema usa
-- uuidv7 por ser ordenable por tiempo, pero acá esa misma propiedad sería
-- una fuga: un id time-ordered reduce el espacio de búsqueda efectivo para
-- quien intenta enumerar shares recientes, y el id es la única barrera
-- contra enumeración de este único endpoint sin sesión de toda la API (ver
-- 04-seguridad-y-amenazas.md §3bis). Sin FK a `resources` — el contenido es
-- un snapshot desacoplado en el momento de creación, no una referencia viva
-- (02-modelo-de-datos.md §6).
create table external_shares (
    id uuid primary key default gen_random_uuid(),
    created_by uuid not null references users(id),
    -- AEAD cifrado client-side con una clave que sólo viaja en el fragmento
    -- de la URL — el servidor jamás la recibe. Nullable: se pisa con NULL
    -- al quemarse (por vistas o por expiración) o al revocarse, para no
    -- conservar el blob sin motivo una vez que ya no es accesible.
    ciphertext bytea,
    password_protected boolean not null default false,
    -- Salt para la capa opcional de passphrase (Argon2id combinado
    -- client-side con la clave del fragmento) — sólo tiene sentido si
    -- `password_protected`, pero no se fuerza con un constraint porque el
    -- Service ya es la única vía de escritura.
    password_salt bytea,
    max_views integer not null default 1,
    view_count integer not null default 0,
    expires_at timestamptz not null,
    revoked_at timestamptz,
    -- Se setea al alcanzar `max_views` o al expirar (lo que ocurra
    -- primero) — momento en el que `ciphertext` se pisa con NULL en la
    -- misma operación.
    burned_at timestamptz,
    created_at timestamptz not null default now()
);

-- Usado por el job de background que quema (borra ciphertext) shares
-- vencidos que nadie llegó a abrir nunca — sin esto, un share con
-- `expires_at` vencido pero cero vistas quedaría con su ciphertext en la
-- tabla indefinidamente, violando el requisito explícito de borrado
-- efectivo, no sólo marcado inactivo.
create index external_shares_sweep_idx on external_shares(expires_at)
    where revoked_at is null and burned_at is null;

-- F-20: política organizacional — el admin puede desactivar la feature
-- completa, fijar un tope de expiración permitido, y exigir la capa de
-- passphrase. Mismo patrón singleton que `password_policy`/
-- `directory_sync_config` (`organization_id` como PK, fila única insertada
-- acá mismo).
create table external_share_policy (
    organization_id integer primary key references organizations(id),
    enabled boolean not null default true,
    max_expiration_hours integer not null default 168,
    require_password boolean not null default false
);

insert into external_share_policy (organization_id) values (1);

-- Aprovecha este mismo ALTER (ya toca `audit_log_entries_event_type_check`
-- para agregar los eventos de F-26) para corregir un mismatch real
-- descubierto al escribir esta migración: `0021_scim.sql`/`0022_directory_sync.sql`
-- dejaron 'sso_config.updated' y 'scim_token.created' en el constraint, pero
-- `AuditEventType::as_db_str()` (audit/models.rs) siempre emitió
-- 'sso.config_updated' y 'scim.token_created' — cada actualización de SSO
-- config y cada creación de token SCIM venía fallando el insert en
-- silencio desde entonces (el consumidor de `DomainEvent::Auditoria` sólo
-- loguea el error, nunca propaga). 'scim_token.revoked' se retira: no
-- existe ningún `AuditEventType` que lo emita (no hay variante de
-- revocación de token SCIM en el código), así que nunca se necesitó en la
-- lista.
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
    'account_recovery_policy.updated',
    'account_recovery.enrolled',
    'account_recovery.requested',
    'account_recovery.approved',
    'account_recovery.completed',
    'password_policy.updated',
    'retention_policy.updated',
    'retention.purge_ran',
    'emergency_access.designated',
    'emergency_access.requested',
    'emergency_access.approved',
    'emergency_access.rejected',
    'emergency_access.accepted',
    'emergency_access.revoked',
    'emergency_access.granted_by_timeout',
    'emergency_access_policy.updated',
    'user.deactivated',
    'user.activated',
    'user.purged',
    'sso.config_updated',
    'sso.login_succeeded',
    'sso.jit_provisioned',
    'sso.account_linked',
    'sso.link_rejected_unverified_email',
    'scim.token_created',
    'scim.user_created',
    'scim.user_updated',
    'scim.user_deactivated',
    'directory_sync.config_updated',
    'directory_sync.dry_run',
    'directory_sync.applied',
    'external_share.created',
    'external_share.accessed',
    'external_share.revoked',
    'external_share.burned',
    'external_share_policy.updated'
));
