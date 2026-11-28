-- Autor: Athan Espinoza

-- ELK-02 (pentest 2026-11-26): revocar un permiso sobre un recurso borraba
-- sólo la fila de `permissions` y dejaba el `secret_envelope` del revocado.
-- Como `listar_destinatarios` lee de `secret_envelopes`, cada edición volvía a
-- cifrar el secreto para él. Desde esta versión el repositorio borra el sobre
-- en la misma transacción; acá se limpian los que ya quedaron huérfanos: sobres
-- de usuarios sin permiso directo ni por ningún grupo sobre el recurso.
delete from secret_envelopes se
where not exists (
    select 1 from permissions p
    where p.subject_type = 'resource' and p.subject_id = se.resource_id
      and p.grantee_type = 'user' and p.grantee_id = se.user_id
)
and not exists (
    select 1 from permissions p
    join group_members gm on gm.group_id = p.grantee_id and gm.user_id = se.user_id
    where p.subject_type = 'resource' and p.subject_id = se.resource_id and p.grantee_type = 'group'
);
