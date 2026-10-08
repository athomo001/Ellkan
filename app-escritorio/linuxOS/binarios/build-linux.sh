#!/usr/bin/env bash
# Autor: Athan Espinoza
# Compila la app de escritorio para Linux con un solo comando, sin preparar nada a mano.
#
# Uso:
#   ./build-linux.sh                         .deb + .rpm + .AppImage
#   ./build-linux.sh --bundles appimage      sólo los formatos indicados (separados por coma)
#   ./build-linux.sh --sin-frontend          reusa frontend/build ya compilado
#   ./build-linux.sh --sin-extension         no vuelve a preparar la extensión de navegador
#
# Lo que hace solo:
#   1. Instala lo que falte (librerías de Tauri con sudo, Rust y pnpm en tu usuario).
#   2. Copia el proyecto a ~/.cache/ellkan-build (disco de Linux). Así no toca los
#      node_modules/ ni target/ de Windows si el repo está en un disco compartido,
#      y la próxima compilación reusa lo ya compilado y es mucho más rápida.
#   3. Compila y deja el resultado en app-escritorio/linuxOS/binarios/ del repo original.

set -euo pipefail

BUNDLES="deb,rpm,appimage"
SIN_FRONTEND=false
SIN_EXTENSION=false
while [ $# -gt 0 ]; do
  case "$1" in
    --bundles) BUNDLES="${2:?falta la lista de formatos, ej. --bundles appimage}"; shift 2 ;;
    --sin-frontend) SIN_FRONTEND=true; shift ;;
    --sin-extension) SIN_EXTENSION=true; shift ;;
    -h|--help) sed -n '3,16p' "$0"; exit 0 ;;
    *) echo "Opción desconocida: $1 (ver --help)" >&2; exit 1 ;;
  esac
done

paso() { echo; echo "==> $*"; }

if [ "$(id -u)" -eq 0 ]; then
  echo "No lo corras como root: Rust y pnpm se instalan en tu usuario y los archivos" >&2
  echo "quedarían con dueño root. Salí de root (exit) y corrélo de nuevo; pide sudo solo cuando hace falta." >&2
  exit 1
fi

DIR_RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TRABAJO="${ELLKAN_BUILD_DIR:-$HOME/.cache/ellkan-build}"
export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"

# --- 1. Requisitos ------------------------------------------------------------

paso "Revisando requisitos"
INSTALO_HERRAMIENTAS=false

PAQUETES_APT=(build-essential curl wget file pkg-config libssl-dev libxdo-dev libwebkit2gtk-4.1-dev
  libayatana-appindicator3-dev librsvg2-dev libfuse2 rsync)
PAQUETES_DNF=(gcc gcc-c++ make curl wget file pkgconf-pkg-config openssl-devel libxdo-devel webkit2gtk4.1-devel
  libappindicator-gtk3-devel librsvg2-devel fuse-libs rsync)

falta_sistema=false
pkg-config --exists webkit2gtk-4.1 2>/dev/null || falta_sistema=true
command -v rsync >/dev/null || falta_sistema=true
command -v curl >/dev/null || falta_sistema=true
[[ ",$BUNDLES," == *",rpm,"* ]] && ! command -v rpmbuild >/dev/null && falta_sistema=true

if [ "$falta_sistema" = true ]; then
  echo "Faltan librerías del sistema; se instalan ahora (pide tu contraseña de sudo)."
  if command -v apt-get >/dev/null; then
    extra=(); [[ ",$BUNDLES," == *",rpm,"* ]] && extra=(rpm)
    sudo apt-get update
    # libfuse2 se llama libfuse2t64 en Ubuntu 24.04+: se prueba con un nombre y después con el otro.
    sudo apt-get install -y "${PAQUETES_APT[@]}" "${extra[@]}" \
      || sudo apt-get install -y "${PAQUETES_APT[@]/libfuse2/libfuse2t64}" "${extra[@]}"
  elif command -v dnf >/dev/null; then
    extra=(); [[ ",$BUNDLES," == *",rpm,"* ]] && extra=(rpm-build)
    sudo dnf install -y "${PAQUETES_DNF[@]}" "${extra[@]}"
  else
    echo "Distribución no reconocida (ni apt ni dnf): instalá a mano WebKitGTK 4.1 y las" >&2
    echo "librerías de Tauri 2 (https://v2.tauri.app/start/prerequisites/#linux) y volvé a correr esto." >&2
    exit 1
  fi
fi

if ! command -v node >/dev/null || [ "$(node -p 'process.versions.node.split(".")[0]')" -lt 22 ]; then
  echo "Instalando Node 22 en tu usuario (~/.local/node)..."
  INSTALO_HERRAMIENTAS=true
  case "$(uname -m)" in x86_64) ARQ=x64 ;; aarch64) ARQ=arm64 ;; *) echo "Arquitectura no soportada: $(uname -m)" >&2; exit 1 ;; esac
  BASE="https://nodejs.org/dist/latest-v22.x"
  TMP="$(mktemp -d)"
  curl -fsSL "$BASE/SHASUMS256.txt" -o "$TMP/SHASUMS256.txt"
  ARCHIVO="$(grep -o "node-v[0-9.]*-linux-$ARQ.tar.xz" "$TMP/SHASUMS256.txt" | head -1)"
  curl -fSL "$BASE/$ARCHIVO" -o "$TMP/$ARCHIVO"
  (cd "$TMP" && grep " $ARCHIVO\$" SHASUMS256.txt | sha256sum -c -)
  rm -rf "$HOME/.local/node" && mkdir -p "$HOME/.local/node" "$HOME/.local/bin"
  tar -xJf "$TMP/$ARCHIVO" -C "$HOME/.local/node" --strip-components=1
  ln -sf "$HOME/.local/node/bin/node" "$HOME/.local/node/bin/npm" "$HOME/.local/node/bin/npx" "$HOME/.local/node/bin/corepack" "$HOME/.local/bin/"
  rm -rf "$TMP"
fi

if ! command -v cargo >/dev/null; then
  echo "Instalando Rust en tu usuario (~/.cargo)..."
  INSTALO_HERRAMIENTAS=true
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
fi

if ! command -v pnpm >/dev/null; then
  echo "Activando pnpm en tu usuario (~/.local/bin)..."
  INSTALO_HERRAMIENTAS=true
  mkdir -p "$HOME/.local/bin"
  corepack enable --install-directory "$HOME/.local/bin"
fi

# --- 2. Copia de trabajo en disco Linux ----------------------------------------

paso "Copiando el proyecto a $TRABAJO"
mkdir -p "$TRABAJO"
# --delete mantiene la copia igual al original; lo excluido (dependencias y
# compilados de Linux) se conserva entre una compilación y la siguiente.
rsync -a --delete \
  --exclude node_modules/ --exclude /target/ --exclude .svelte-kit/ --exclude /frontend/build/ \
  --exclude /app-escritorio/src-tauri/extension-bundle/ --exclude '*.msi' --exclude '*.exe' --exclude '*.zip' \
  --exclude '*.AppImage' --exclude '*.deb' --exclude '*.rpm' --exclude .git/ \
  "$DIR_RAIZ/" "$TRABAJO/"
cd "$TRABAJO"

export SQLX_OFFLINE="true"

paso "Instalando dependencias de JavaScript"
(cd frontend && pnpm install --frozen-lockfile)
if [ "$SIN_EXTENSION" = false ]; then (cd extension && pnpm install --frozen-lockfile); fi

# Los bindings wasm del cripto (frontend/src/lib/wasm) no se versionan: si no
# vinieron con la copia, se generan.
if [ ! -f frontend/src/lib/wasm/ellkan_crypto.js ]; then
  paso "Generando los bindings wasm del cripto"
  command -v wasm-pack >/dev/null || curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
  wasm-pack build --target web --out-dir ../../frontend/src/lib/wasm crates/ellkan-crypto
fi

# --- 3. Compilar ---------------------------------------------------------------

if [ "$SIN_FRONTEND" = false ]; then
  paso "Compilando el frontend"
  pnpm --prefix frontend build
fi

if [ "$SIN_EXTENSION" = false ]; then
  paso "Preparando la extensión de navegador (va dentro de la app)"
  node app-escritorio/scripts/preparar-extension.mjs
fi

paso "Compilando la app y empaquetando: $BUNDLES (la primera vez tarda varios minutos)"
pnpm --prefix frontend tauri build --bundles "$BUNDLES"

# --- 4. Resultado al repo original ----------------------------------------------

DESTINO="$DIR_RAIZ/app-escritorio/linuxOS/binarios"
paso "Copiando el resultado a $DESTINO"
for f in target/release/bundle/deb/*.deb target/release/bundle/rpm/*.rpm target/release/bundle/appimage/*.AppImage; do
  if [ -f "$f" ]; then cp -vf "$f" "$DESTINO/"; fi
done

echo
echo "Listo. Archivos en: $DESTINO"
if [ "$INSTALO_HERRAMIENTAS" = true ]; then
  echo
  echo "Se instalaron herramientas nuevas (Rust/Node/pnpm). Para usarlas a mano en esta"
  echo "terminal corré 'source ~/.cargo/env' o abrí una terminal nueva."
fi
