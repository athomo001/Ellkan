-- Autor: Athan Espinoza

-- F-58: tokens y API keys de terceros (GitHub, OpenAI, AWS, OAuth…) como tipo
-- propio. `key_id` es la parte pública de un par id+secreto y `token_secret`
-- su secreto; `expires_at` va dentro de la metadata cifrada, así que el
-- servidor nunca ve cuándo vence un token. Shape distinto al de los tipos
-- usuario/contraseña: no se puede cambiar de tipo hacia/desde éste.
insert into resource_types (slug, json_schema) values
    ('api-token', '{"metadata": ["name", "uri", "username", "key_id", "scopes", "expires_at"], "secret": ["token", "token_secret", "notes"]}')
on conflict (slug) do nothing;
