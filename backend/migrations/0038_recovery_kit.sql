-- Autor: Athan Espinoza

-- Recovery kit: recuperación self-service sin admin (par X25519 generado en
-- el cliente, la privada nunca toca el servidor). Independiente de F-16
-- (`account_recovery`, escrow contra la clave org + aprobación de N admins)
-- — modelos de confianza opuestos, ver spec/04-seguridad-y-amenazas.md §6.
create table recovery_kits (
    id uuid primary key default uuidv7(),
    user_id uuid not null unique references users(id) on delete cascade,
    kit_public_key_x25519 bytea not null,
    sealed_identity_material bytea not null,
    -- true tras un reset exitoso vía este kit: el kit ya se usó/expuso, se
    -- fuerza reemplazo en el próximo login (ver recovery_kit::service).
    must_rotate boolean not null default false,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

-- Token de un solo uso para el link de reset por email — a diferencia de los
-- códigos de 6 dígitos que ya usa el resto de la app (email_verification_challenges,
-- device_challenges, mfa_challenges), este endpoint no tiene sesión ni nada
-- más atado, así que necesita más entropía: 32 bytes CSPRNG, no 6 dígitos.
create table recovery_reset_tokens (
    id uuid primary key default uuidv7(),
    user_id uuid not null references users(id) on delete cascade,
    token_hash bytea not null,
    expires_at timestamptz not null,
    consumed_at timestamptz,
    -- sólo se llenan si el usuario no tiene TOTP confirmado (fallback MFA
    -- de este flujo) — ver recovery_kit::service::enviar_codigo_email.
    email_code_hash bytea,
    email_code_expires_at timestamptz,
    created_at timestamptz not null default now()
);
create index recovery_reset_tokens_user_id_idx on recovery_reset_tokens(user_id);
create index recovery_reset_tokens_token_hash_idx on recovery_reset_tokens(token_hash);

-- Nuevos eventos de auditoría: recovery_kit.* (módulo nuevo) y
-- account_recovery.rejected (F-16 gana rechazar, delegado a admin de grupo
-- igual que aprobar, ver account_recovery::service).
alter table audit_log_entries drop constraint audit_log_entries_event_type_check;
alter table audit_log_entries add constraint audit_log_entries_event_type_check check (event_type in (
    'auth.login_succeeded',
    'auth.login_failed',
    'auth.device_unrecognized',
    'auth.device_verified',
    'auth.device_verification_failed',
    'auth.device_auto_verified_no_smtp',
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
    'metadata_key.member_added',
    'role.created',
    'role.permissions_updated',
    'device_approval_policy.updated',
    'mfa.enrolled',
    'mfa_policy.updated',
    'account_recovery_policy.updated',
    'account_recovery.enrolled',
    'account_recovery.requested',
    'account_recovery.approved',
    'account_recovery.rejected',
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
    'external_share_policy.updated',
    'export_policy.updated',
    'export.performed',
    'import.performed',
    'users.exported',
    'groups.exported',
    'backup.created',
    'backup.failed',
    'backup.restored',
    'restore.failed',
    'cli.cleanup_ran',
    'cli.user_promoted',
    'cli.recovery_setup_issued',
    'passkey.revoked',
    'resource.updated',
    'smtp_config.updated',
    'user.passphrase_changed',
    'self_registration_policy.updated',
    'user.email_verified',
    'resource.deleted',
    'recovery_kit.generated',
    'recovery_kit.reset_requested',
    'recovery_kit.reset_completed',
    'recovery_kit.reset_mfa_failed'
));
