-- Autor: Athan Espinoza

-- F-49 fase 3.3: "Conectar" para Escritorio remoto (rdp) y bases de datos
-- (postgresql / mysql / mongodb). Mismo formato que ssh/ftp/telnet/vnc
-- (host:puerto en `uri`), así que entre todos se puede cambiar el tipo
-- (`PUT /resources/{id}/type` compara `json_schema`).
insert into resource_types (id, slug, json_schema) values
    ('019a0000-0000-7000-8000-000000000007', 'rdp', '{"metadata": ["name", "username", "uri"], "secret": ["password", "notes"]}'),
    ('019a0000-0000-7000-8000-000000000008', 'postgresql', '{"metadata": ["name", "username", "uri"], "secret": ["password", "notes"]}'),
    ('019a0000-0000-7000-8000-000000000009', 'mysql', '{"metadata": ["name", "username", "uri"], "secret": ["password", "notes"]}'),
    ('019a0000-0000-7000-8000-00000000000a', 'mongodb', '{"metadata": ["name", "username", "uri"], "secret": ["password", "notes"]}');
