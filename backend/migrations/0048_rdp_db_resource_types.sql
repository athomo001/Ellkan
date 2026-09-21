-- Autor: Athan Espinoza

-- Mismo criterio que 0035_telnet_resource_type.sql: tipos nuevos con el mismo
-- formato que ssh/ftp/telnet/vnc (host:puerto en `uri`), para que "Conectar"
-- de la app de escritorio (F-49, fase 3.3) los cubra: Escritorio remoto y
-- bases de datos. Sin esto, sincronizar (F-47) un recurso `rdp`/`postgresql`/…
-- contra un servidor que no los conoce fallaría con "tipo desconocido".
insert into resource_types (slug, json_schema) values
    ('rdp', '{"metadata": ["name", "username", "uri"], "secret": ["password", "notes"]}'),
    ('postgresql', '{"metadata": ["name", "username", "uri"], "secret": ["password", "notes"]}'),
    ('mysql', '{"metadata": ["name", "username", "uri"], "secret": ["password", "notes"]}'),
    ('mongodb', '{"metadata": ["name", "username", "uri"], "secret": ["password", "notes"]}')
on conflict (slug) do nothing;
