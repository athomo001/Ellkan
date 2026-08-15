-- Autor: Athan Espinoza

-- Hallazgo de seguridad (auditoría 2026-08-12, H-27): a diferencia de
-- `emergency_access_requests` (0017), que sí tiene un índice único parcial
-- para "un solo pending a la vez", `account_recovery_requests` no lo tenía
-- — ni la aplicación lo validaba. `POST /account-recovery/requests` es sin
-- sesión (sólo email), así que un atacante podía invocarlo repetidamente
-- contra el email de una víctima, insertando una fila `pending` nueva cada
-- vez y disparando una notificación real a los admins en cada una
-- (mail-bombing, agrava H-09).
create unique index account_recovery_requests_pendiente_unica_idx
    on account_recovery_requests(escrow_id) where status = 'pending';
