-- Autor: Athan Espinoza

-- Avatar de perfil (opcional) — a diferencia de casi todo lo demás en este
-- schema, no es un dato secreto/cifrado: es metadata pública del perfil,
-- igual criterio que `display_name` (nunca formó parte del modelo
-- zero-knowledge), así que se guarda en claro.
alter table users add column avatar_bytes bytea;
alter table users add column avatar_content_type text;
