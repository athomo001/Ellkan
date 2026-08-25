-- Autor: Athan Espinoza

-- Correos con diseño real (multipart texto+HTML) en vez de sólo texto plano
-- — `html_body` nullable a propósito: filas ya encoladas antes de este
-- cambio (o el email de prueba de `/admin/smtp`, que sigue siendo sólo
-- texto) quedan sin parte HTML, `notificaciones::enviar` manda texto plano
-- si es null en vez de fallar.
alter table outbound_emails add column html_body text;
