-- Autor: Athan Espinoza

-- ELK-01 (#147), defensa en profundidad.
--
-- (c) Una cuenta creada por SSO-JIT, SCIM o directory-sync que todavía no
-- enroló sus claves ya NO tiene fila en `user_keys`. Antes nacía con claves
-- públicas `[0;32]` y blob vacío: la Ed25519 en ceros permitía forjar firmas
-- (cerrado con `verify_strict`), y la X25519 en ceros aparecía en el buscador
-- de destinatarios: un secreto compartido con esa cuenta quedaba sellado con
-- un secreto Diffie-Hellman nulo, que cualquiera con el ciphertext podía abrir.
-- Sin fila, todos los `join user_keys` (login, buscador, destinatarios,
-- recuperación) la dejan afuera solos. `POST /me/keys/enroll` pasa a insertar.

delete from user_keys where octet_length(encrypted_private_key_blob) = 0;
-- Una purga de esas cuentas registraba la clave en ceros como revocada.
delete from cuentas_revocadas where public_key_ed25519 = '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea;

-- Que no vuelva a entrar una fila de relleno por ningún camino.
alter table user_keys
    add constraint user_keys_blob_no_vacio check (octet_length(encrypted_private_key_blob) > 0),
    add constraint user_keys_x25519_no_nula check (public_key_x25519 <> '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea),
    add constraint user_keys_ed25519_no_nula check (public_key_ed25519 <> '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea);

-- (a2) El enrolamiento exige una sesión emitida por el callback SSO (y
-- reciente): una prueba independiente del login por firma. Una sesión que no
-- vino del IdP, aunque fuera válida, no puede crear las claves de la cuenta.
alter table sessions add column emitida_por_sso boolean not null default false;
