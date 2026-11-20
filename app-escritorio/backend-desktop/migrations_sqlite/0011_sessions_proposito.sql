-- Autor: Athan Espinoza

-- Mismo propósito explícito de sesión que en el servidor: una sesión parcial
-- sólo habilita la operación por la que se emitió (verificar MFA, configurar
-- el primer segundo factor o cambiar una passphrase provisoria), nunca el
-- resto de la API.
alter table sessions add column proposito text not null default 'completa'
    check (proposito in ('completa', 'mfa_pendiente', 'mfa_configurar', 'cambiar_passphrase'));

-- Sesiones parciales previas: no se sabe para qué se emitieron, se revocan.
update sessions
   set proposito = 'mfa_pendiente',
       revoked_at = coalesce(revoked_at, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
 where mfa_verified_at is null;
