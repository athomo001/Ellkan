-- Autor: Athan Espinoza

-- Propósito explícito de cada sesión. Hasta acá una sesión parcial
-- (`mfa_verified_at` nulo) era intercambiable: la emitida para "verificá tu
-- código MFA" podía usarse para configurar un TOTP nuevo y completarse sola,
-- sin conocer nunca el segundo factor real. Ahora cada sesión parcial sólo
-- sirve para la operación por la que se emitió:
--   * completa           — sesión normal, todo el resto de la API.
--   * mfa_pendiente      — sólo `POST /auth/mfa/verify`.
--   * mfa_configurar     — sólo `POST /me/mfa/totp/{setup,confirm}`.
--   * cambiar_passphrase — sólo `POST /me/change-passphrase`.
alter table sessions
    add column proposito text not null default 'completa'
        check (proposito in ('completa', 'mfa_pendiente', 'mfa_configurar', 'cambiar_passphrase'));

-- Las sesiones parciales vivas al momento de migrar no tienen forma segura
-- de saber para qué se emitieron: se revocan (duran a lo sumo 12 horas y el
-- usuario sólo tiene que volver a iniciar sesión). Quedan marcadas con un
-- propósito restringido para que, aun revocadas, nunca pasen por completas.
update sessions
   set proposito = 'mfa_pendiente',
       revoked_at = coalesce(revoked_at, now())
 where mfa_verified_at is null;

-- Invariante: sólo una sesión con MFA verificado puede ser "completa".
alter table sessions
    add constraint sessions_proposito_coherente
        check ((proposito = 'completa') = (mfa_verified_at is not null));
