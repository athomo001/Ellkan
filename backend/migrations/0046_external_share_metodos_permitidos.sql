-- Autor: Athan Espinoza

-- F-26, hallazgo real de uso 2026-08-24: el toggle "enabled" ya existía
-- pero el frontend nunca lo consultaba (el botón "Compartir externo"
-- seguía visible aunque el admin lo hubiera apagado). De paso, el archivo
-- .7z (alternativa sin servidor, misma sesión) necesita su propio permiso
-- separado del link: técnicamente NO se puede exigir server-side (nunca
-- toca el servidor), así que estos dos campos son una política de UI, no
-- una barrera técnica real — mismo criterio que cualquier otra política
-- que sólo controla qué botones se ofrecen, documentado así en el código.
alter table external_share_policy add column allow_link boolean not null default true;
alter table external_share_policy add column allow_file boolean not null default true;
