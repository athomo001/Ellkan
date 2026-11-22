-- Autor: Athan Espinoza
--
-- QA-16 (pendiente #107): `Alice@x.com` y `alice@x.com` eran dos cuentas
-- distintas. Ahora el email es único sin distinguir mayúsculas y toda
-- búsqueda compara `lower(email)`. Los emails guardados NO se reescriben: el
-- email es el AAD del blob de la clave privada, y cambiarlo dejaría el blob
-- sin poder abrirse. El servidor devuelve el email guardado en
-- `/auth/key-material` para que el cliente abra el blob con ése.
--
-- Si ya hay cuentas que sólo difieren en mayúsculas, la migración se frena
-- con la lista: hay que resolverlas a mano (desactivar o borrar una de las
-- dos, o cambiarle el email desde el panel) y volver a arrancar.

do $$
declare
    duplicados text;
begin
    select string_agg(grupo, '; ')
      into duplicados
      from (
            select string_agg(email, ', ' order by created_at) as grupo
              from users
             group by lower(email)
            having count(*) > 1
           ) g;
    if duplicados is not null then
        raise exception 'Hay cuentas cuyo email sólo difiere en mayúsculas: %. Dejá una sola por email (desactivá o borrá las otras, o cambiales el email) y volvé a arrancar el servidor.', duplicados;
    end if;
end
$$;

create unique index users_email_lower_key on users (lower(email));
alter table users drop constraint users_email_key;
