-- Autor: Athan Espinoza

-- F-33: snapshot de cuántos recursos había cifrados con la clave saliente en
-- el momento exacto en que arranca la rotación — necesario para que
-- `GET /admin/metadata-keys/rotation-status` pueda reportar "cuántos había
-- al iniciar" además de "cuántos quedan" (el conteo de pendientes en sí se
-- recalcula en vivo contra `resources`, no se snapshotea).
alter table metadata_keys add column resources_pendientes_al_iniciar integer;
