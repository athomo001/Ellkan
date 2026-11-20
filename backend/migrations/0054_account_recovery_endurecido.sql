-- Autor: Athan Espinoza

-- Endurecimiento de Account Recovery (F-16).
--
-- 1) Quién agregó a cada miembro de un grupo. Un manager de grupo puede
--    aprobar la recuperación de un miembro de su grupo; sin este dato podía
--    agregar a cualquier usuario a su grupo y acto seguido aprobar la
--    recuperación de esa cuenta. `null` = alta del sistema (Directory Sync,
--    creación del grupo) o anterior a esta migración.
alter table group_members
    add column added_by uuid references users(id) on delete set null;

-- 2) Ciclo de vida de la solicitud:
--    unconfirmed -> pending (el dueño del email confirmó el código)
--                -> approved (umbral alcanzado) -> completed
--    más rejected y expired. El admin sólo ve solicitudes `pending`: una
--    solicitud que nadie confirmó desde el correo de la cuenta nunca llega a
--    pedir aprobación.
alter table account_recovery_requests drop constraint account_recovery_requests_status_check;
alter table account_recovery_requests add constraint account_recovery_requests_status_check
    check (status in ('unconfirmed', 'pending', 'approved', 'rejected', 'completed', 'expired'));
alter table account_recovery_requests alter column status set default 'unconfirmed';

-- Código enviado al email de la cuenta (sólo su hash SHA-256) y tope de
-- intentos, mismo criterio que `device_challenges` (0052).
alter table account_recovery_requests add column confirmation_code_hash bytea;
alter table account_recovery_requests add column confirmation_failed_attempts integer not null default 0;

-- Token del solicitante (sólo su hash SHA-256): se entrega al confirmar el
-- código y es lo único que permite consultar el material sellado y
-- completar la recuperación. Sin él, conocer el `id` de la solicitud no
-- alcanza para nada.
alter table account_recovery_requests add column requester_token_hash bytea;

-- Vencimiento: una solicitud no queda abierta para siempre.
alter table account_recovery_requests
    add column expires_at timestamptz not null default (now() + interval '72 hours');

-- Las solicitudes abiertas previas no tienen token ni confirmación del
-- dueño del email: no se pueden completar de forma segura. Se vencen; quien
-- todavía la necesite vuelve a pedirla.
update account_recovery_requests
   set status = 'expired', resolved_at = coalesce(resolved_at, now())
 where status in ('pending', 'approved');
