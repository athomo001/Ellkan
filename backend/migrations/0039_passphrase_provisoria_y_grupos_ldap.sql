-- Autor: Athan Espinoza

-- Cambio de passphrase obligatorio para claves provisorias: un admin que
-- crea un usuario (POST /admin/users) conoce la passphrase temporal a
-- propósito (zero-knowledge roto para esa cuenta puntual) — hasta ahora no
-- había ningún enforcement real de que se cambiara. Mismo criterio "sin
-- gracia" que ya rige para MFA obligatorio (mfa_policy.require_mfa).
alter table users add column must_change_passphrase boolean not null default false;

-- Directory Sync (F-19): filtro base de usuario configurable (antes
-- hardcodeado a inetOrgPerson, no servía tal cual contra Active Directory)
-- y sync de grupos vía un atributo multivaluado en la propia entrada de
-- usuario (memberOf, estilo Active Directory — también funciona en
-- OpenLDAP con el overlay memberof activado).
alter table directory_sync_config add column user_object_class text not null default 'inetOrgPerson';
alter table directory_sync_config add column sync_groups boolean not null default false;
alter table directory_sync_config add column group_membership_attribute text not null default 'memberOf';

-- `true` sólo para grupos raíz creados por Directory Sync (find-or-create
-- por nombre) — la reconciliación de salida (alguien ya no aparece en el
-- memberOf) sólo toca grupos con esta marca, nunca uno armado a mano aunque
-- comparta nombre.
alter table groups add column managed_by_directory_sync boolean not null default false;
