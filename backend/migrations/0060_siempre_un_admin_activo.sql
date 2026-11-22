-- Autor: Athan Espinoza
--
-- QA-38 (pendiente #108): la instancia nunca se queda sin un administrador
-- activo. Antes un token SCIM (o un admin bloqueándose o purgándose a sí
-- mismo, o el sync de directorio) podía dejarla sin nadie que la administre.
--
-- La regla vive acá y no en cada servicio para que la cumplan todos los
-- caminos (SCIM, panel web, purga, directory sync, SQL a mano). Es un
-- trigger de restricción diferido: se evalúa al confirmar la transacción,
-- así una operación que saca a un admin y promueve a otro en la misma
-- transacción no falla a mitad de camino. Sólo actúa si la fila tocada ERA
-- un admin activo: una instancia que ya estuviera sin admins no queda
-- bloqueada para cualquier otro cambio.
--
-- El lock consultivo serializa dos bajas simultáneas de admins distintos:
-- sin él, cada una vería a la otra todavía activa y las dos pasarían.

create function asegurar_un_admin_activo() returns trigger
language plpgsql as $$
begin
    if not (old.active and old.deleted_at is null
            and exists (select 1 from role_permissions rp where rp.role_id = old.role_id and rp.permission = '*')) then
        return null;
    end if;

    perform pg_advisory_xact_lock(hashtext('ellkan:un-admin-activo'));

    if not exists (
        select 1 from users u
        join role_permissions rp on rp.role_id = u.role_id
        where rp.permission = '*' and u.active and u.deleted_at is null
    ) then
        raise exception 'debe quedar al menos un administrador activo'
            using errcode = 'EK001';
    end if;
    return null;
end
$$;

create constraint trigger users_un_admin_activo
    after update of active, deleted_at, role_id or delete on users
    deferrable initially deferred
    for each row execute function asegurar_un_admin_activo();
