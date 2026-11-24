#!/usr/bin/env bash
# Autor: Athan Espinoza
#
# Instalador del servidor Ellkan para Linux y macOS (Docker). Hace todo lo
# que el README pedía a mano: crea el .env, genera los secretos, levanta los
# contenedores, espera a que el servidor responda y muestra (y abre, si hay
# navegador) el link para crear la cuenta de administrador con el token de
# instalación ya puesto.
#
# Uso (desde la carpeta del repo):
#   bash instalar.sh
#
# Se puede correr las veces que haga falta: no regenera secretos que ya
# existen ni toca una base que ya tiene datos. No necesita openssl.

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if [ -t 1 ]; then
  CIAN=$'\033[36m'; VERDE=$'\033[32m'; ROJO=$'\033[31m'; NORMAL=$'\033[0m'
else
  CIAN=''; VERDE=''; ROJO=''; NORMAL=''
fi
paso() { printf '\n%s==> %s%s\n' "$CIAN" "$1" "$NORMAL"; }
ok() { printf '    %s%s%s\n' "$VERDE" "$1" "$NORMAL"; }
info() { printf '    %s\n' "$1"; }
detener() {
  printf '\n%sNo se pudo terminar la instalación:%s\n%s\n' "$ROJO" "$NORMAL" "$1" >&2
  exit 1
}

# --- 1. Docker ----------------------------------------------------------------
paso "Revisando Docker"
command -v docker >/dev/null 2>&1 || detener "Docker no está instalado. Instalalo (https://docs.docker.com/engine/install/) y volvé a correr este instalador."
command -v curl >/dev/null 2>&1 || detener "Falta curl. Instalalo (por ejemplo: sudo apt install curl) y volvé a correr este instalador."

if ! salida_info="$(docker info 2>&1)"; then
  if printf '%s' "$salida_info" | grep -qi 'permission denied'; then
    detener "Tu usuario no tiene permiso para usar Docker. Agregalo al grupo docker:
    sudo usermod -aG docker \"\$USER\"
cerrá la sesión, volvé a entrar y corré este instalador de nuevo."
  fi
  detener "Docker no responde. Arrancalo (sudo systemctl start docker, o abrí Docker Desktop en macOS) y volvé a correr este instalador."
fi
docker compose version >/dev/null 2>&1 || detener "Falta Docker Compose v2 (el comando 'docker compose'). Instalá el plugin docker-compose-plugin y volvé a correr este instalador."
ok "Docker listo."

# --- 2. Configuración (.env) --------------------------------------------------
paso "Configuración (.env)"
if [ ! -f .env ]; then
  cp .env.example .env
  ok "Creé .env a partir de .env.example (valores por defecto)."
else
  ok "Uso el .env que ya existe."
fi

# Se lee el .env acá mismo (sin `source`: no se ejecuta nada de su contenido).
valor_config() {
  local clave="$1" por_defecto="$2" valor
  valor="$(sed -nE "s/^[[:space:]]*${clave}[[:space:]]*=[[:space:]]*(.*)$/\1/p" .env | tail -n 1 | sed -E "s/[[:space:]]+$//; s/^[\"']//; s/[\"']$//")"
  printf '%s' "${valor:-$por_defecto}"
}
usuario_base="$(valor_config POSTGRES_USER ellkan)"
nombre_base="$(valor_config POSTGRES_DB ellkan)"
puerto="$(valor_config ELLKAN_PORT 8080)"
url="http://localhost:${puerto}"

# --- 3. Secretos --------------------------------------------------------------
paso "Secretos (carpeta secrets/)"
mkdir -p secrets
leer_secreto() { if [ -f "$1" ]; then tr -d '\r\n' < "$1"; fi; }
# Sin salto de línea: quedaría pegado a la contraseña dentro del contenedor.
escribir_secreto() { umask 077; printf '%s' "$2" > "$1"; }
hex_aleatorio() { head -c "$1" /dev/urandom | od -An -v -tx1 | tr -d ' \n'; }
base64_aleatorio() { head -c "$1" /dev/urandom | base64 | tr -d '\n'; }

# ¿Ya hay una base creada? Si la hay, sus secretos no se pueden regenerar: la
# base guarda la contraseña en su volumen y la clave de secretos protege
# datos ya cifrados.
proyecto="$(docker compose config --format json 2>/dev/null | sed -nE 's/^[[:space:]]*\{?[[:space:]]*"name":[[:space:]]*"([^"]+)".*/\1/p' | head -n 1)"
[ -n "$proyecto" ] || detener "No pude leer docker-compose.yml: $(docker compose config 2>&1 | tail -n 5)"
base_existe=""
if [ -n "$(docker volume ls -q --filter "label=com.docker.compose.project=${proyecto}" --filter "label=com.docker.compose.volume=postgres_data")" ]; then
  base_existe="si"
fi
reinstalar="Si esta instalación no tiene datos que te importen, borrala y empezá de cero con:
    docker compose down -v
y volvé a correr este instalador."

contrasena="$(leer_secreto secrets/postgres_password.txt)"
if [ -z "$contrasena" ]; then
  [ -z "$base_existe" ] || detener "Falta secrets/postgres_password.txt, pero la base de datos ya existe y necesita la contraseña con la que se creó.
$reinstalar"
  contrasena="$(hex_aleatorio 24)"
  escribir_secreto secrets/postgres_password.txt "$contrasena"
  ok "Generé la contraseña de la base de datos."
else
  ok "La contraseña de la base de datos ya existe: la conservo."
fi

if [ -z "$(leer_secreto secrets/ellkan_secrets_key.txt)" ]; then
  [ -z "$base_existe" ] || detener "Falta secrets/ellkan_secrets_key.txt, pero la base de datos ya existe y tiene datos cifrados con esa clave.
$reinstalar"
  escribir_secreto secrets/ellkan_secrets_key.txt "$(base64_aleatorio 32)"
  ok "Generé la clave de secretos del servidor."
else
  ok "La clave de secretos ya existe: la conservo."
fi

# La URL se arma siempre desde el .env y la contraseña: así nunca queda
# desincronizada.
url_base="postgres://${usuario_base}:${contrasena}@ellkan-db:5432/${nombre_base}"
if [ "$(leer_secreto secrets/database_url.txt)" != "$url_base" ]; then
  escribir_secreto secrets/database_url.txt "$url_base"
  ok "Escribí la conexión a la base (usuario '${usuario_base}', base '${nombre_base}')."
else
  ok "La conexión a la base ya está bien."
fi

# --- 4. Levantar ----------------------------------------------------------------
paso "Levantando Ellkan (la primera vez descarga las imágenes)"
docker compose up -d || detener "'docker compose up' falló (el error está arriba). Si dice que el puerto está en uso, cambiá ELLKAN_PORT o POSTGRES_PORT en .env."

# --- 5. Esperar a que responda ----------------------------------------------------
paso "Esperando a que el servidor responda en ${url}"
estado=""
limite=$(( $(date +%s) + 180 ))
while [ "$(date +%s)" -lt "$limite" ]; do
  codigo="$(curl -s -o /tmp/ellkan-setup-status.$$ -w '%{http_code}' --max-time 5 "${url}/auth/setup-status" || true)"
  if [ "$codigo" = "200" ]; then estado="$(cat /tmp/ellkan-setup-status.$$)"; break; fi
  # 404: imagen anterior a la 0.1.71, sin /auth/setup-status, pero el servidor está arriba.
  if [ "$codigo" = "404" ]; then estado="sin-setup-status"; break; fi
  reinicios="$(docker inspect -f '{{.RestartCount}}' ellkan 2>/dev/null || echo 0)"
  if [ "${reinicios:-0}" -ge 3 ] 2>/dev/null; then
    detener "El servidor se reinicia una y otra vez. Últimas líneas de su log:
$(docker compose logs --no-log-prefix --tail 15 ellkan 2>&1)

Si dice 'password authentication failed', la base se creó con otros datos: $reinstalar"
  fi
  sleep 3
done
rm -f /tmp/ellkan-setup-status.$$
[ -n "$estado" ] || detener "El servidor no respondió en 3 minutos. Últimas líneas de su log:
$(docker compose logs --no-log-prefix --tail 15 ellkan 2>&1)"
ok "El servidor responde."

# --- 6. Primera cuenta ----------------------------------------------------------
paso "Cuenta de administrador"
abrir="$url"
if [ "$estado" = "sin-setup-status" ]; then
  info "Esta versión de Ellkan es anterior a la 0.1.71 y NO pide token de instalación:"
  info "creá tu cuenta ya, antes de dejar el servidor accesible desde la red."
  abrir="${url}/register"
elif printf '%s' "$estado" | grep -q '"setup_token_required":true'; then
  # El último: el token cambia en cada arranque mientras no haya cuentas.
  token="$(docker compose logs --no-log-prefix ellkan 2>&1 | sed -nE 's/.*token de instalaci[^ ]*n: ([0-9a-f]{48}).*/\1/p' | tail -n 1)"
  if [ -n "$token" ]; then
    abrir="${url}/register#setup=${token}"
    info "Token de instalación: ${token}"
    info "(sirve para crear la primera cuenta, que queda como administradora; cambia si el servidor se reinicia antes)"
  else
    # Token propio configurado con ELLKAN_SETUP_TOKEN[_FILE]: no sale en el log.
    info "Esta instalación usa un token de instalación propio (ELLKAN_SETUP_TOKEN): pegalo en la pantalla de registro."
    abrir="${url}/register"
  fi
else
  info "Este servidor ya tiene cuentas: entrá con la tuya."
fi

printf '\n%sListo. Ellkan está en %s%s\n' "$VERDE" "$url" "$NORMAL"
printf '%sAbrí este link para seguir: %s%s\n' "$VERDE" "$abrir" "$NORMAL"
if command -v xdg-open >/dev/null 2>&1 && [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]; then
  xdg-open "$abrir" >/dev/null 2>&1 || true
elif command -v open >/dev/null 2>&1 && [ "$(uname -s)" = "Darwin" ]; then
  open "$abrir" || true
fi
