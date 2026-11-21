-- Autor: Athan Espinoza

-- QA-22: cuando un contacto pide acceso de emergencia, el titular recibe un
-- email, y otro a mitad del plazo si todavía no respondió. Esta columna marca
-- que el recordatorio ya salió, para que el job no lo mande en cada vuelta.
alter table emergency_access_requests add column reminder_sent_at timestamptz;
