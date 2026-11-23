-- Autor: Athan Espinoza
--
-- QA-03: igual que la migración 0064 del servidor. Cada blob guarda los
-- parámetros de Argon2id con que se selló y el verificador de la
-- `auth_key`; `null` = bóveda sellada antes de QA-03, que el cliente
-- re-sella en su siguiente desbloqueo (`POST /me/kdf-upgrade`).

alter table user_keys add column kdf_params text not null default '{"m_cost_kib":19456,"t_cost":2,"p_cost":1}';
alter table user_keys add column auth_verifier blob;
