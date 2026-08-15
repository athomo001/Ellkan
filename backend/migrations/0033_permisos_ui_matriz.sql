-- Autor: Athan Espinoza

-- Módulo 1 (RBAC granular, inspirado en Passbolt): matriz visual de
-- permisos en el panel admin. El catálogo de `role_permissions` ya era
-- abierto (0004_roles.sql) — esto sólo siembra las filas por default que
-- preservan el comportamiento actual del rol `user` (hoy nadie está
-- restringido en ninguna de estas acciones, así que todas nacen "Permitir"
-- salvo `groups.create`, que ya era admin-only de forma hardcodeada).
--
-- Sin nueva tabla ni `user_permissions_override`: un admin que quiera
-- delegar sólo `groups.create` a un usuario puntual crea un rol custom con
-- ese único permiso (ya soportado por `POST /admin/roles`) y se lo asigna
-- — el catálogo abierto ya cubre el caso de uso.
insert into role_permissions (role_id, permission)
select id, permiso
from roles, unnest(array[
    'import.use',
    'export.use',
    'password.preview',
    'password.copy',
    'folders.use',
    'folder.share'
]) as permiso
where name = 'user';
