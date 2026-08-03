# Autor: Athan Espinoza

# Multi-stage: el builder compila el binario estático, la imagen final no
# lleva toolchain ni shell.

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

# Las migraciones quedan embebidas en el binario en tiempo de compilación
# (`sqlx::migrate!`), no se leen de disco en runtime — nada que copiar acá.

# Sin shell en la imagen final: no hay `ENV SECRET=valor` posible ni forma de
# leer variables sensibles por accidente vía `docker exec` interactivo.
USER nonroot
EXPOSE 8080
ENTRYPOINT ["/app/ellkan-backend"]
