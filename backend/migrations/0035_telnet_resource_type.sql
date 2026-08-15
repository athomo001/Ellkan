-- Autor: Athan Espinoza

-- Hallazgo real de uso 2026-08-11: mismo criterio que
-- 0032_ftp_ssh_vnc_resource_types.sql — un tipo más que el usuario pidió
-- explícitamente (comando de conexión copiable para SSH/FTP/Telnet).
insert into resource_types (slug, json_schema) values
    ('telnet', '{"metadata": ["name", "username", "uri"], "secret": ["password", "notes"]}');
