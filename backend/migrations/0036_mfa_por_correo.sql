-- Autor: Athan Espinoza

-- Hallazgo real de uso 2026-08-11: "agreguemos aparte de totp el mfa por
-- correo y que el admin elija entre esos 2 o nada". `mfa_challenges.method`
-- estaba cerrado a 'totp' desde 0014_mfa.sql — se abre a 'email'. Un
-- desafío de método 'email' necesita su propio código de un solo uso (no
-- hay nada que "verificar" del lado servidor para TOTP, el código vive en
-- la app del usuario, pero para email el servidor genera el código y tiene
-- que poder compararlo — mismo patrón hash-only que `device_challenges.code_hash`).
alter table mfa_challenges drop constraint mfa_challenges_method_check;
alter table mfa_challenges add constraint mfa_challenges_method_check check (method in ('totp', 'email'));
alter table mfa_challenges add column code_hash bytea;
