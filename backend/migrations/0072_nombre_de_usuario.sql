-- Autor: Athan Espinoza

-- F-47 C (pendiente #49): entrar con el correo o con un nombre de usuario.
-- Opcional, lo elige cada persona en su perfil. Se guarda en minúsculas;
-- sin `@` (así nunca se confunde con un correo) y de 3 a 32 caracteres.
alter table users
    add column username text check (username ~ '^[a-z0-9][a-z0-9._-]{2,31}$');

create unique index users_username_idx on users (username) where username is not null and deleted_at is null;
