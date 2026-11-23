-- Autor: Athan Espinoza
--
-- QA-03: `POST /auth/key-material` entregaba el blob de la clave privada a
-- cualquiera que conociera el email, para crackear la passphrase offline.
-- Desde ahora el cliente deriva del mismo Argon2id una `auth_key` (HKDF con
-- otro `info`) y el servidor guarda sólo su verificador (SHA-256 con
-- dominio): el blob se entrega a quien la prueba.
--
-- `null` = cuenta sellada antes de QA-03 (parámetros viejos, sin
-- verificador): sigue recibiendo el blob como antes hasta su siguiente
-- desbloqueo, en el que el cliente la re-sella (`POST /me/kdf-upgrade`).
-- `kdf_params` ya existía (default 19 MiB / t=2) pero nadie lo leía; ahora
-- viaja con el blob y todo blob nuevo trae el suyo.

alter table user_keys
    add column auth_verifier bytea
        check (auth_verifier is null or octet_length(auth_verifier) = 32);
