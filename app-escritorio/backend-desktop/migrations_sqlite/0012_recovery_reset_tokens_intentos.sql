-- Autor: Athan Espinoza

-- Mismo tope de intentos que en el servidor (QA-23); en escritorio el reset
-- es local (firma con el kit), pero el repositorio comparte el contrato.
alter table recovery_reset_tokens add column failed_attempts integer not null default 0;
