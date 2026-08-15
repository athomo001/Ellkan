-- Autor: Athan Espinoza

-- F-08: recursos que incluyen TOTP junto con la contraseña — el secreto
-- TOTP viaja dentro del mismo envelope cifrado que la contraseña (no un
-- objeto aparte), mismo criterio que `login-password` de Fase 0.
insert into resource_types (slug, json_schema) values (
    'login-password-totp',
    '{"metadata": ["name", "username", "uri"], "secret": ["password", "notes", "totp_secret"]}'
);
