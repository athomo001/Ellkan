#!/usr/bin/env bash
# Autor: Athan Espinoza
#
# Pendiente #91: las notas de cada Release salen de CHANGELOG.md, no de los
# títulos de los PR (que se llaman «Develop» y dejaban la lista vacía).
#
# Uso: notas-del-changelog.sh <sección>
#   <sección> = X.Y.Z para una Release oficial, o «Sin publicar» para la
#   pre-release de develop.
# Imprime el cuerpo de esa sección (desde su `## [...]` hasta el siguiente,
# sin el título). Si no existe o está vacía, lo dice en una línea en vez de
# fallar: la Release se publica igual.

set -euo pipefail

seccion="${1:?falta la sección (X.Y.Z o «Sin publicar»)}"
archivo="${2:-CHANGELOG.md}"

cuerpo=$(awk -v s="## [$seccion]" '
  index($0, s) == 1 { dentro = 1; next }
  dentro && /^## \[/ { exit }
  dentro { print }
' "$archivo" | sed -e '/./,$!d')

# Quitar líneas en blanco del final.
cuerpo=$(printf '%s\n' "$cuerpo" | sed -e :a -e '/^\n*$/{$d;N;ba' -e '}')

if [ -z "${cuerpo//[[:space:]]/}" ]; then
  echo "_Sin cambios anotados en CHANGELOG.md para «$seccion»._"
else
  printf '%s\n' "$cuerpo"
fi
