-- Autor: Athan Espinoza

-- F-48: soporte real para los modos "sólo-memoria"/"sólo-nombres" (spec/13
-- §8) — un recurso pulleado en modo conectado sin réplica completa del
-- secreto necesita igual el DEK sellado para poder descifrar su metadata
-- offline (metadata y secreto comparten la misma DEK para recursos
-- `user_key`). Esta tabla existe sólo para ese caso: un recurso con el
-- secreto replicado normalmente (modo `Full`, o cualquier cosa creada en
-- esta misma máquina) nunca tiene fila acá — el DEK ya vive en
-- `secret_envelopes` junto al secreto real.
create table metadata_deks (
    resource_id text primary key,
    user_id text not null,
    sealed_dek blob not null,
    created_at text not null default (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
