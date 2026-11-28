-- Autor: Athan Espinoza

-- spec/15 §3 (pendiente #52): verificación contra el directorio LDAP en el
-- login y cada pocos minutos de sesión, para que una baja en AD corte el
-- acceso aunque el sync no haya corrido.

-- Quién gestiona la cuenta. Sólo `directory_sync` se verifica contra el
-- directorio; `scim` empuja los cambios él mismo (F-18); null = local.
alter table users
    add column managed_by text check (managed_by in ('directory_sync', 'scim')),
    add column last_directory_check_at timestamptz;

-- Cuentas que ya trajo el sync de LDAP: si la instancia tiene LDAP
-- configurado y nunca emitió un token de SCIM, toda cuenta con
-- `external_id` vino del directorio. Si hay SCIM también, no se adivina: el
-- próximo «aplicar» del sync las marca.
update users set managed_by = 'directory_sync', last_directory_check_at = now()
 where external_id is not null
   and exists (select 1 from directory_sync_config where ldap_url is not null)
   and not exists (select 1 from scim_tokens);

-- §3.2: qué hacer si el directorio no responde. `grace` deja entrar sólo si
-- la última verificación buena de ESE usuario tiene menos de
-- `grace_seconds`; `deny` no deja entrar nunca. No existe «permitir sin
-- límite». `session_revalidate_seconds`: cada cuánto se re-verifica una
-- sesión abierta (extensión, escritorio).
alter table directory_sync_config
    add column directory_unreachable_policy text not null default 'grace'
        check (directory_unreachable_policy in ('grace', 'deny')),
    add column grace_seconds integer not null default 900 check (grace_seconds between 0 and 86400),
    add column session_revalidate_seconds integer not null default 300 check (session_revalidate_seconds between 30 and 86400);
