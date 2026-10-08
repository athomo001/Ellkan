-- Autor: Athan Espinoza

-- F-58: tokens y API keys de terceros. Mismo `json_schema` que la migración
-- de Postgres, para que el sync (F-47) reconozca el tipo en los dos lados.
insert into resource_types (id, slug, json_schema) values
    ('019a0000-0000-7000-8000-00000000000b', 'api-token', '{"metadata": ["name", "uri", "username", "key_id", "scopes", "expires_at"], "secret": ["token", "token_secret", "notes"]}');
