-- Autor: Athan Espinoza

-- Hallazgo de seguridad (auditoría 2026-08-12, H-06): `verificar_totp` sólo
-- validaba el código contra la ventana ±1 paso (90s) sin rastrear el último
-- paso aceptado — un código observado (shoulder-surfing, captura de
-- pantalla) podía reutilizarse en un segundo login concurrente dentro de esa
-- ventana, porque la única protección contra reuso era invalidar el
-- *challenge* de sesión, no el código TOTP en sí. `ultimo_paso_aceptado`
-- guarda el contador RFC 6238 (`unix_time / 30`) del último código
-- efectivamente aceptado para este credential — un intento con un paso menor
-- o igual se rechaza sin siquiera compararlo (ver
-- `TotpCredentialRepository::marcar_paso_aceptado`, comparación-y-swap
-- atómica contra condiciones de carrera entre dos verificaciones
-- concurrentes con el mismo código).
alter table user_totp_credentials add column ultimo_paso_aceptado bigint;
