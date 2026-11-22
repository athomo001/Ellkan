-- Autor: Athan Espinoza

-- QA-31: un login SSO ya no vincula sola una cuenta local que tenga el mismo
-- email. La vinculación se pide desde una sesión ya iniciada
-- (`POST /me/sso/link`); el `state` de ese flujo recuerda a qué cuenta va.
alter table sso_login_state add column link_user_id uuid references users(id) on delete cascade;
