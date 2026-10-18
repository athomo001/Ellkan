-- Autor: Athan Espinoza

-- Tope de intentos por desafío de verificación de dispositivo (F-02).
-- Hasta acá lo único que frenaba adivinar el código del correo era el límite
-- de solicitudes por IP. Ese límite se relaja (2026-10-17) para que muchas
-- personas detrás de la misma NAT puedan entrar a la vez, así que el tope
-- pasa a vivir en el propio desafío: a los 5 códigos incorrectos queda
-- consumido y hay que pedir uno nuevo (nuevo login).
alter table device_challenges add column failed_attempts integer not null default 0;

-- Mismo tope para el código de verificación de cuenta al registrarse (F-24),
-- que tenía el mismo hueco.
alter table email_verification_challenges add column failed_attempts integer not null default 0;
