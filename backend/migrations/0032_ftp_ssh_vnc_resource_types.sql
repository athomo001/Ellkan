-- Autor: Athan Espinoza

-- F-07: tres tipos de recurso nuevos (FTP/SSH/VNC) — mismo criterio que
-- `login-password-totp` (0010_totp_resource_type.sql): el servidor es
-- zero-knowledge y nunca valida campos dentro del blob cifrado, así que
-- agregar un tipo es sólo una fila nueva en `resource_types` con un
-- `json_schema` descriptivo. Reusan el mismo shape que `login-password`
-- (name/username/uri en metadata, password/notes en secret) — `uri` alcanza
-- para `host:puerto` (ej. `ftp://host:21`); sin autenticación por clave SSH
-- todavía, eso es un feature bastante más grande y no fue pedido.

insert into resource_types (slug, json_schema) values
    ('ftp', '{"metadata": ["name", "username", "uri"], "secret": ["password", "notes"]}'),
    ('ssh', '{"metadata": ["name", "username", "uri"], "secret": ["password", "notes"]}'),
    ('vnc', '{"metadata": ["name", "username", "uri"], "secret": ["password", "notes"]}');
