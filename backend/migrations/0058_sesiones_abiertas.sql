-- Autor: Athan Espinoza
--
-- QA-21 (pendiente #110): se quita la aprobación de un dispositivo nuevo
-- desde otro (F-37) y los dispositivos de confianza. El pedido de aprobación
-- nacía sin sesión y, una vez aprobado, entregaba una sesión completa sin
-- pasar por MFA. Entrar ya exige contraseña, verificación del dispositivo por
-- email y MFA si la política lo pide: en su lugar, cada usuario ve sus
-- sesiones abiertas y puede cerrar las otras (`/me/sessions`).
--
-- Los tipos de evento de auditoría `device.*` y
-- `device_approval_policy.updated` se dejan en el check: el log histórico
-- puede tenerlos.

drop table device_approval_requests;
drop table trusted_devices;

alter table organizations drop column allow_peer_device_approval;
alter table organizations drop column allow_admin_device_approval;

-- Sólo un nombre corto del navegador y el sistema ("Chrome · Windows"),
-- nunca el User-Agent completo ni la IP (minimización, pendiente #21).
alter table sessions add column dispositivo text;
alter table sessions add column last_used_at timestamptz;
