-- Autor: Athan Espinoza

-- QA-23: tope de intentos de segundo factor por token de reset del recovery
-- kit. Antes un mismo token admitía intentos ilimitados durante su hora de
-- vida (sólo los frenaba el límite por IP); al llegar al tope el token queda
-- consumido y hay que pedir uno nuevo.
alter table recovery_reset_tokens add column failed_attempts integer not null default 0;
