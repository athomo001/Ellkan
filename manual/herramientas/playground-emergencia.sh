#!/usr/bin/env bash
# Autor: Athan Espinoza
#
# Playground del acceso de emergencia (F-36, pendiente #134): deja listo el
# stack local de `docker compose` para recorrer el flujo con clics, sin
# esperar días al plazo.
#
# Uso (desde la raíz del repo, con `docker compose up -d` ya corriendo):
#   bash manual/herramientas/playground-emergencia.sh preparar
#       Habilita la política de acceso de emergencia de la organización.
#   bash manual/herramientas/playground-emergencia.sh conceder <correo-del-contacto>
#       Simula que venció el plazo: atrasa la solicitud pendiente de ese
#       contacto y reinicia el servidor, cuyo job la concede al arrancar.
#   bash manual/herramientas/playground-emergencia.sh estado
#       Muestra las relaciones y su última solicitud.
#
# Recorrido sugerido (dos navegadores o una ventana privada):
#   1. Crear dos cuentas: titular y contacto. Con el titular, cargar 2–3
#      claves en la bóveda.
#   2. Titular: Ajustes → Acceso de emergencia → designar al contacto
#      (comparar la huella con la que el contacto ve en «Mis claves»).
#   3. Contacto: Ajustes → Acceso de emergencia → Aceptar → Pedir acceso.
#   4. O el titular aprueba (camino corto), o se corre `conceder` (camino
#      del plazo vencido).
#   5. Contacto: «Ver bóveda» → ve las claves del titular, sólo lectura.
#   6. Admin: Auditoría → aparece `emergency_access.vault_viewed`.
#   7. Titular: revocar → el contacto ya no puede abrirla.
#
# Sólo toca la base local del compose (contenedor `ellkan-db`). No usar
# contra una instancia real: `conceder` saltea la espera que protege al
# titular.

set -euo pipefail

contenedor="${ELLKAN_DB_CONTAINER:-ellkan-db}"
usuario="${POSTGRES_USER:-ellkan}"
base="${POSTGRES_DB:-ellkan}"

psql() {
  docker exec -i "$contenedor" psql -v ON_ERROR_STOP=1 -U "$usuario" -d "$base" "$@"
}

case "${1:-}" in
  preparar)
    psql -c "update organizations set emergency_access_enabled = true where id = 1;"
    echo "Política de acceso de emergencia habilitada."
    ;;
  conceder)
    correo="${2:?falta el correo del contacto}"
    # Atrasa la solicitud pendiente más allá del plazo y reinicia el servidor:
    # el job de F-36 corre al arrancar y la concede por el camino real
    # (estado `confirmed` + evento de auditoría). psql -v pasa el correo como
    # literal escapado (:'correo'), nunca interpolado en el SQL.
    filas=$(psql -qtA -v correo="$correo" <<'SQL'
update emergency_access_requests r
   set requested_at = now() - make_interval(days => ea.wait_time_days + 1)
  from emergency_access ea
  join users u on u.id = ea.grantee_id
 where r.emergency_access_id = ea.id
   and r.status = 'pending'
   and lower(u.email) = lower(:'correo')
returning r.id;
SQL
)
    if [ -z "$filas" ]; then
      echo "No hay solicitudes pendientes de $correo (¿ya pidió acceso desde su cuenta?)." >&2
      exit 1
    fi
    docker restart "${ELLKAN_CONTAINER:-ellkan}" >/dev/null
    echo "Plazo vencido para $filas; el servidor se reinició y la concede al arrancar."
    ;;
  estado)
    psql -c "
select g.email as titular, c.email as contacto, ea.access_level, ea.status,
       (select r.status from emergency_access_requests r
         where r.emergency_access_id = ea.id order by r.requested_at desc limit 1) as solicitud
  from emergency_access ea
  join users g on g.id = ea.granter_id
  join users c on c.id = ea.grantee_id
 order by ea.created_at;"
    ;;
  *)
    sed -n '4,30p' "$0"
    exit 2
    ;;
esac
