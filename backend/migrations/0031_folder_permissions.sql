-- Autor: Athan Espinoza

-- F-09/F-11: carpetas ganan permisos tipo Passbolt (`permissions.subject_type
-- = 'folder'`, ya soportado por el schema desde Fase 1.1 pero sin usar).
-- Compartir una carpeta exige que su nombre pueda estar sellado por-usuario
-- (mismo criterio que ya vale para recursos vía `secret_envelopes`) — hoy
-- `folders.name_ciphertext` es una sola columna sellada sólo contra quien la
-- creó, no alcanza para un segundo destinatario. Se mueve a `folder_items`
-- (que ya es la tabla por-usuario, una fila por `(item, user)`), quedando
-- `folders` como sólo el `id` compartido entre todas las vistas.

alter table folder_items add column name_ciphertext bytea;
alter table folder_items add column name_nonce bytea;
alter table folder_items add column name_key_id uuid;

-- Backfill: cada fila de folder_items que hoy representa una carpeta
-- (child_folder_id no nulo) hereda el nombre que tenía en `folders`.
update folder_items fi
set name_ciphertext = f.name_ciphertext, name_nonce = f.name_nonce, name_key_id = f.name_key_id
from folders f
where fi.child_folder_id = f.id;

alter table folder_items add constraint folder_items_name_solo_en_carpetas check (
    (child_folder_id is not null and name_ciphertext is not null and name_nonce is not null) or
    (child_folder_id is null and name_ciphertext is null and name_nonce is null)
);

alter table folders drop column name_ciphertext;
alter table folders drop column name_nonce;
alter table folders drop column name_key_id;

-- Sin cambios al catálogo de audit_log_entries.event_type: compartir una
-- carpeta reusa `AuditEventType::PermissionGranted` (`permission.granted`),
-- ya genérico por `subject_type` (`con_sujeto("resource"|"folder", id)`),
-- mismo evento que ya audita compartir un recurso.
