-- Autor: Athan Espinoza

-- Bug real encontrado probando en la ventana real (2026-09-16): el Vault
-- ofrece SSH/FTP/VNC/Telnet/TOTP como tipos de recurso seleccionables sin
-- saber que está en modo escritorio, pero `0003_resources.sql` sólo había
-- sembrado `login-password` — crear cualquier otro tipo fallaba con
-- "resource_type_slug desconocido" (`desktop/router.rs::crear_recurso`).
-- Mismo catálogo que el modo servidor (Postgres: 0010_totp_resource_type.sql
-- + 0032_ftp_ssh_vnc_resource_types.sql + 0035_telnet_resource_type.sql) —
-- el catálogo de tipos de recurso no es un concepto multiusuario (spec/12
-- §4), se porta completo.
insert into resource_types (id, slug, json_schema) values
    ('019a0000-0000-7000-8000-000000000002', 'login-password-totp', '{"metadata": ["name", "username", "uri"], "secret": ["password", "notes", "totp_secret"]}'),
    ('019a0000-0000-7000-8000-000000000003', 'ftp', '{"metadata": ["name", "username", "uri"], "secret": ["password", "notes"]}'),
    ('019a0000-0000-7000-8000-000000000004', 'ssh', '{"metadata": ["name", "username", "uri"], "secret": ["password", "notes"]}'),
    ('019a0000-0000-7000-8000-000000000005', 'vnc', '{"metadata": ["name", "username", "uri"], "secret": ["password", "notes"]}'),
    ('019a0000-0000-7000-8000-000000000006', 'telnet', '{"metadata": ["name", "username", "uri"], "secret": ["password", "notes"]}');
