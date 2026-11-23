#!/usr/bin/env bash
# Autor: Athan Espinoza
#
# Pendiente #80: la web y la extensión no cargan nada de terceros. Ni
# analítica ni CDNs: una contraseña maestra se tipea en estas páginas, y un
# script ajeno tendría acceso a todo. Falla si el build final menciona alguno
# de estos dominios. Uso: sin-terceros.sh <carpeta> [<carpeta>...]
#
# Única excepción conocida: los íconos de sitios de la extensión
# (`www.google.com/s2/favicons`), apagados por defecto y opcionales
# (pendiente #126). No es un dominio de esta lista.

set -euo pipefail

DOMINIOS=(
	'google-analytics\.com'
	'googletagmanager\.com'
	'doubleclick\.net'
	'connect\.facebook\.net'
	'segment\.(io|com)'
	'mixpanel\.com'
	'amplitude\.com'
	'hotjar\.com'
	'posthog\.com'
	'plausible\.io'
	'clarity\.ms'
	'fullstory\.com'
	'heapanalytics\.com'
	'sentry\.io'
	'cdn\.jsdelivr\.net'
	'unpkg\.com'
	'cdnjs\.cloudflare\.com'
	'fonts\.googleapis\.com'
	'fonts\.gstatic\.com'
	'ajax\.googleapis\.com'
	'code\.jquery\.com'
	'stackpath\.bootstrapcdn\.com'
	'cdn\.skypack\.dev'
	'esm\.sh'
)
patron=$(IFS='|'; echo "${DOMINIOS[*]}")

if [ "$#" -eq 0 ]; then
	echo "uso: $0 <carpeta> [<carpeta>...]" >&2
	exit 2
fi
for carpeta in "$@"; do
	if [ ! -d "$carpeta" ]; then
		echo "no existe $carpeta (¿falta el build?)" >&2
		exit 2
	fi
done

if grep -rEn --binary-files=without-match "($patron)" "$@"; then
	echo "::error::el build menciona un dominio de analítica o CDN externo (arriba)" >&2
	exit 1
fi
echo "sin dominios de analítica ni CDN externos en: $*"
