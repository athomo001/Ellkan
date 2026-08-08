# Autor: Athan Espinoza

# Multi-stage: `wasm-builder` genera los bindings de `ellkan-crypto` que
# `frontend-builder` necesita para compilar el sitio estático, `builder`
# compila el binario del backend — la imagen final no lleva ni toolchain ni
# shell, sólo el binario y el build estático de `frontend/` (`ServeDir` +
# fallback SPA, `backend/src/lib.rs`).

FROM rust:1-slim-bookworm AS wasm-builder
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/*
RUN curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh

COPY rust-toolchain.toml Cargo.toml Cargo.lock ./
COPY crates/ellkan-crypto ./crates/ellkan-crypto
# El `Cargo.toml` raíz declara un workspace con `backend`/`cli` como
# miembros — `cargo metadata` (que `wasm-pack` corre primero) resuelve el
# workspace entero aunque sólo se compile `ellkan-crypto`, así que sus
# manifests (con target real, no alcanza con el `Cargo.toml` solo) tienen
# que existir acá aunque este stage no compile su código.
COPY backend ./backend
COPY cli ./cli
# `--out-dir` apunta directo al mismo destino que usa un desarrollador local
# (ver `docs/activeContext.md`) — `frontend/src/lib/wasm/` es gitignored,
# se regenera siempre a partir de la fuente Rust, nunca se commitea.
RUN wasm-pack build --target web --out-dir /wasm-out crates/ellkan-crypto

FROM node:24-slim AS frontend-builder
WORKDIR /build
RUN corepack enable
COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY frontend ./
COPY --from=wasm-builder /wasm-out ./src/lib/wasm
RUN pnpm run build

FROM rust:1-slim-bookworm AS builder
WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY .sqlx ./.sqlx
COPY crates/ellkan-crypto ./crates/ellkan-crypto
COPY backend ./backend
COPY cli ./cli

# `SQLX_OFFLINE=true` usa el caché `.sqlx/` (generado con `cargo sqlx
# prepare`, commiteado al repo) en vez de conectarse a una base real — el
# build de la imagen no tiene ni debe tener acceso a Postgres.
ENV SQLX_OFFLINE=true
RUN cargo build --release -p ellkan-backend

FROM gcr.io/distroless/cc-debian12:nonroot
WORKDIR /app

COPY --from=builder /build/target/release/ellkan-backend /app/ellkan-backend
COPY --from=frontend-builder /build/build /app/frontend

# Las migraciones quedan embebidas en el binario en tiempo de compilación
# (`sqlx::migrate!`), no se leen de disco en runtime — nada que copiar acá.

ENV ELLKAN_FRONTEND_DIST=/app/frontend

# Sin shell en la imagen final: no hay `ENV SECRET=valor` posible ni forma de
# leer variables sensibles por accidente vía `docker exec` interactivo.
USER nonroot
EXPOSE 8080
ENTRYPOINT ["/app/ellkan-backend"]
