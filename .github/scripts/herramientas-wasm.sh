#!/usr/bin/env bash
# Autor: Athan Espinoza
#
# Instala las dos herramientas que `wasm-pack build` necesita, ANTES de
# correrlo, para que no las baje él a mitad del build.
#
# Por qué: wasm-pack 0.15.0 busca `wasm-opt` en el PATH y, si no está, lo baja
# de GitHub (binaryen version_117) sin reintentos ni checksum; un corte de red
# tira el build entero (pasó en el job de la imagen Docker:
# «failed to download … binaryen-version_117-x86_64-linux.tar.gz»). Con
# `wasm-bindgen` hace lo mismo, aunque si la descarga falla lo compila.
# Si los dos ya están en el PATH (`wasm-opt` cualquiera; `wasm-bindgen` con la
# versión exacta de Cargo.lock), wasm-pack los usa y no descarga nada
# (src/wasm_opt.rs::find_wasm_opt e install/mod.rs::download_prebuilt_or_cargo_install).
#
# Qué hace:
#   - binaryen: la MISMA versión que usaría wasm-pack (version_117), con
#     reintentos y verificada contra un SHA-256 fijado acá (no el .sha256 que
#     viene al lado: ése lo controla el mismo servidor que el archivo).
#   - wasm-bindgen-cli: la versión de `wasm-bindgen` en Cargo.lock (los
#     bindings exigen coincidencia exacta), compilada desde crates.io con
#     `--locked`. Si ya está instalada esa versión, no hace nada.
#
# Uso:
#   bash .github/scripts/herramientas-wasm.sh <carpeta-destino>
# Deja `wasm-opt` en <carpeta-destino>/bin. En GitHub Actions agrega esa
# carpeta al PATH de los pasos siguientes; en otro lado (Dockerfile), agregala
# vos (`ENV PATH=…`).
#
# Para subir binaryen: cambiar BINARYEN_VERSION y los dos hashes (están en
# `https://github.com/WebAssembly/binaryen/releases/download/<versión>/<archivo>.sha256`;
# confirmarlos bajando el archivo y corriendo `sha256sum`).

set -euo pipefail

BINARYEN_VERSION="version_117"
SHA256_LINUX_X64="3dc677006555b355ea2da5e82602065a161d5e83eaefd3f759afa00b96e83212"
SHA256_WINDOWS_X64="b09f260176483bd30194303ccb15ac81c2247e4e566894f9d931e4313cb36d58"

destino="${1:?uso: herramientas-wasm.sh <carpeta-destino>}"
raiz="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# --- binaryen (wasm-opt) -----------------------------------------------------
# macOS (#82–#87): el tarball de binaryen para Mac no trae `wasm-opt` estático
# (depende de `lib/libbinaryen.dylib`), así que ahí se usa Homebrew (bottles
# firmados; wasm-pack acepta cualquier `wasm-opt` del PATH, ver arriba).
if [ "$(uname -s)" = "Darwin" ]; then
  mkdir -p "$destino/bin"
  destino="$(cd "$destino" && pwd)"
  command -v wasm-opt >/dev/null || brew install binaryen
  wasm-opt --version
else
  case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) plataforma="x86_64-linux"; esperado="$SHA256_LINUX_X64"; exe="wasm-opt" ;;
    MINGW*-x86_64 | MSYS*-x86_64 | CYGWIN*-x86_64)
      plataforma="x86_64-windows"; esperado="$SHA256_WINDOWS_X64"; exe="wasm-opt.exe" ;;
    *)
      echo "herramientas-wasm: plataforma sin hash fijado: $(uname -s)-$(uname -m)" >&2
      exit 1 ;;
  esac

  archivo="binaryen-${BINARYEN_VERSION}-${plataforma}.tar.gz"
  url="https://github.com/WebAssembly/binaryen/releases/download/${BINARYEN_VERSION}/${archivo}"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

  echo "herramientas-wasm: bajando $archivo"
  # --retry-all-errors reintenta también los 5xx y los cortes a mitad de la
  # descarga, que es lo que falla de verdad contra los assets de GitHub.
  curl --fail --silent --show-error --location \
    --retry 8 --retry-delay 5 --retry-all-errors --connect-timeout 30 \
    --output "$tmp/$archivo" "$url"

  calculado="$(sha256sum "$tmp/$archivo" | cut -d' ' -f1)"
  if [ "$calculado" != "$esperado" ]; then
    echo "herramientas-wasm: SHA-256 de $archivo no coincide" >&2
    echo "  esperado:  $esperado" >&2
    echo "  calculado: $calculado" >&2
    exit 1
  fi

  mkdir -p "$destino/bin"
  destino="$(cd "$destino" && pwd)"   # GITHUB_PATH necesita una ruta absoluta
  # En los dos tarballs wasm-opt viene enlazado estático: alcanza con el ejecutable.
  tar -xzf "$tmp/$archivo" -C "$tmp" "binaryen-${BINARYEN_VERSION}/bin/$exe"
  install -m 0755 "$tmp/binaryen-${BINARYEN_VERSION}/bin/$exe" "$destino/bin/$exe"
  "$destino/bin/$exe" --version
fi

# --- wasm-bindgen-cli ----------------------------------------------------------
# Primera `version = "…"` después de `name = "wasm-bindgen"` en Cargo.lock.
version_bindgen="$(awk '/^name = "wasm-bindgen"$/ { getline; gsub(/version = |"/, ""); print; exit }' "$raiz/Cargo.lock")"
if ! [[ "$version_bindgen" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "herramientas-wasm: no encontré la versión de wasm-bindgen en Cargo.lock ('$version_bindgen')" >&2
  exit 1
fi

if command -v wasm-bindgen >/dev/null && [ "$(wasm-bindgen --version | awk '{print $2}')" = "$version_bindgen" ]; then
  echo "herramientas-wasm: wasm-bindgen $version_bindgen ya instalado"
else
  echo "herramientas-wasm: instalando wasm-bindgen-cli $version_bindgen desde crates.io"
  CARGO_NET_RETRY="${CARGO_NET_RETRY:-10}" cargo install wasm-bindgen-cli --locked --version "$version_bindgen"
fi
wasm-bindgen --version

if [ -n "${GITHUB_PATH:-}" ]; then
  # GITHUB_PATH espera una ruta nativa: en Windows, C:\… en vez de /c/….
  if command -v cygpath >/dev/null; then
    cygpath -w "$destino/bin" >> "$GITHUB_PATH"
  else
    echo "$destino/bin" >> "$GITHUB_PATH"
  fi
fi
