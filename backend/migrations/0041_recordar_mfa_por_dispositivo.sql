-- Autor: Athan Espinoza

-- Hallazgo real de uso (2026-08-13): con MFA requerido, el código se pedía
-- en TODOS los logins, incluso desde un dispositivo ya conocido (F-02) —
-- ni Passbolt ni Proton son así de reiterativos, ambos recuerdan el
-- segundo factor por dispositivo una vez verificado. Se reusa exactamente
-- el mismo mecanismo de confianza que F-02 (`known_devices`, identificado
-- por el mismo `device_token_hash` persistido en localStorage) en vez de
-- inventar un mecanismo de "recordarme" paralelo — mismo modelo de
-- confianza, un solo lugar donde vive.

alter table known_devices add column mfa_verified_at timestamptz;
