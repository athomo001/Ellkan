#!/usr/bin/env bash
# Autor: Athan Espinoza
# Script de empaquetado y generación de binarios para Linux (.deb, .rpm, .AppImage)

set -euo pipefail

echo "======================================================="
echo " Generando binarios nativos de Ellkan para Linux       "
echo " (.deb, .rpm, .AppImage)                               "
echo "======================================================="

# Asegurar variables de compilación offline para SQLX
export SQLX_OFFLINE="true"

# Directorio raíz del proyecto
DIR_RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$DIR_RAIZ"

# 1. Compilar frontend estático
echo "[1/3] Compilando frontend estático para empaquetado..."
pnpm --prefix frontend build

# 1b. Preparar la extensión de navegador (Chromium + Firefox) para embeberla
#     en el ejecutable — cada build de escritorio trae la última versión.
echo "[1b/3] Preparando la extensión de navegador..."
node app-escritorio/scripts/preparar-extension.mjs

# 2. Compilar aplicación Tauri con targets de Linux
echo "[2/3] Empaquetando ejecutables e instaladores con Tauri..."
pnpm --prefix frontend tauri build --bundles deb,rpm,appimage

# 3. Copiar artefactos resultantes al directorio de distribución
echo "[3/3] Copiando artefactos a app-escritorio/linuxOS/binarios/..."
DESTINO="$DIR_RAIZ/app-escritorio/linuxOS/binarios"
ORIGEN_BUNDLE="$DIR_RAIZ/target/release/bundle"

if [ -d "$ORIGEN_BUNDLE/deb" ]; then
  cp -vf "$ORIGEN_BUNDLE"/deb/*.deb "$DESTINO/" || true
fi

if [ -d "$ORIGEN_BUNDLE/rpm" ]; then
  cp -vf "$ORIGEN_BUNDLE"/rpm/*.rpm "$DESTINO/" || true
fi

if [ -d "$ORIGEN_BUNDLE/appimage" ]; then
  cp -vf "$ORIGEN_BUNDLE"/appimage/*.AppImage "$DESTINO/" || true
fi

echo "======================================================="
echo " Empaquetado completado exitosamente en: $DESTINO       "
echo "======================================================="
