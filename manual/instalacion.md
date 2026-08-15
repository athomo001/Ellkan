# Instalación, TLS, backup/restore y troubleshooting

## Modos de instalación

### Docker Compose (oficial, recomendado)

Ver [README.md](../README.md#instalación-rápida) para el paso a paso completo. Un solo comando (`docker compose up -d`) levanta `ellkan` (backend + frontend servidos del mismo binario) y `ellkan-db` (Postgres 18). Las migraciones corren automáticamente al arrancar — no hay paso manual de `migrate`.

Por defecto el backend sirve HTTP plano en `${ELLKAN_PORT:-8080}` — Ellkan nunca termina TLS él mismo salvo que se lo configures explícitamente (ver abajo). Sin nada delante, ese tráfico va sin cifrar en la red — aceptable sólo en `localhost`/una red ya confiable; para cualquier otro caso, elegí una de las dos opciones siguientes.

### TLS: dos formas de cerrar el canal, sin depender de un reverse proxy aparte

**Opción A — Ellkan termina TLS él mismo (recomendado si no querés un contenedor más).** El binario soporta `axum-server`+`rustls` de forma nativa: dos variables de entorno con la ruta a un cert/key PEM, sin proxy ni segundo proceso.

```bash
# 1. Conseguí un cert+key (self-signed para probar, o real vía certbot/tu CA)
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes -subj "/CN=tu-dominio.com"
```

Agregá al `environment:` del servicio `ellkan` en `docker-compose.yml`:

```yaml
environment:
  # ...lo que ya había...
  ELLKAN_TLS_CERT_FILE: /certs/cert.pem
  ELLKAN_TLS_KEY_FILE: /certs/key.pem
volumes:
  - ./certs:/certs:ro
```

Las dos variables tienen que estar juntas — con sólo una, el binario falla al arrancar con un error explícito en vez de degradar a HTTP silenciosamente. Con las dos, el puerto configurado pasa a servir HTTPS directamente.

**Opción B — reverse proxy delante** (Caddy, nginx, Traefik) si preferís separar responsabilidades (WAF, renovación automática de Let's Encrypt sin gestionarla vos, etc.) — cualquiera de los tres sirve, no hay una integración especial de Ellkan con ninguno en particular; apuntalo al puerto HTTP interno de `ellkan` como backend.

No hay una tercera opción real: el canal tiene que cerrarse en algún punto entre el navegador/extensión y el servidor. La Opción A es la más liviana porque no agrega contenedor ni proceso nuevo.

## Backup y restauración

Comandos completos en [manual/cli.md](cli.md#comandos) (`ellkan-cli admin backup create`/`backup restore`). Puntos operativos que no están ahí:

- **El backup es del sistema completo** (todas las tablas vía `pg_dump` en streaming, cifrado con [`age`](https://github.com/FiloSottile/age) antes de tocar disco — nunca queda un dump en claro) — no hay backup parcial (sólo-vault, sólo-usuarios, etc.) en v1.
- **La clave privada `age` de restauración no vive en la instancia** — guardala aparte (gestor de secretos, un lugar frío) desde el mismo momento en que generás el par de claves. Perder esa clave privada hace el backup irrecuperable — no hay puerta trasera, es cifrado real.
- **Restaurar es destructivo sobre la base destino** — pensalo como "reemplazar", no "fusionar". El flujo recomendado para migrar de servidor: levantar el `docker-compose.yml` nuevo con la base vacía (migraciones corren solas al arrancar), después `backup restore` apuntando su `DATABASE_URL` a esa base recién creada, antes de exponerla a usuarios reales.
- **Restaurar no reimporta `ellkan_secrets_key.txt`** — ese archivo es del *servidor* (cifra en reposo el TOTP de login), no de los datos. Si el backup se restaura en una instancia nueva con una `ellkan_secrets_key` distinta a la original, todo TOTP de login ya configurado queda indescifrable — cada usuario tiene que reconfigurar su TOTP. Para evitar esto, restaurá también el `ellkan_secrets_key.txt` original junto con los datos, guardado en el mismo lugar frío que la clave `age`.

## Problemas comunes y cómo repararlos

| Síntoma | Causa | Reparación |
| --- | --- | --- |
| El contenedor `ellkan` no arranca, log menciona una migración | Migraciones corren automáticamente al boot (forward-only, sin rollback) — una migración que falla a mitad de camino puede dejar el schema en un estado intermedio | Revisá el log completo del contenedor (`docker logs ellkan`) para identificar cuál migración falló; si es un `CHECK`/`UNIQUE` violado por datos preexistentes de una versión vieja, hace falta limpiar esos datos a mano antes de reintentar — no hay downgrade automático |
| `ellkan-cli` no puede conectar a Postgres aunque el contenedor esté sano | `DATABASE_URL` de la CLI (host) usa `localhost:${POSTGRES_PORT}`, **no** el mismo valor que `secrets/database_url.txt` (que usa el hostname interno `ellkan-db`, sólo resuelve dentro de la red de Docker) | Usar el `DATABASE_URL` armado con `localhost`, ver el snippet en [manual/cli.md](cli.md#administración-ellkan-cli-admin-subcomando) |
| `ellkan-cli`/`docker` no ven el daemon aunque Docker Desktop esté corriendo (Linux con Docker Desktop instalado) | El contexto de Docker activo puede seguir apuntando al socket de Docker Desktop en vez del daemon real del sistema — nos pasó en desarrollo | `docker context ls` para confirmar, `docker context use default` para volver al daemon real |
| `docker compose up` falla con el password de Postgres / la URL no parsea bien el puerto | `postgres_password.txt` generado con caracteres que rompen una URL (`+`, `/` — típico si se generó con `base64` en vez de `hex`) | Regenerar con `openssl rand -hex 24` (nunca `base64`) para ese archivo puntual — ver [secrets/README.md](../secrets/README.md) |
| Login nuevo pide un código por email y nunca llega | SMTP no configurado todavía — el poller de envío es un stub hasta que se configure un relay real | Configurar SMTP en `/admin/smtp` (necesita un admin ya existente — para el primer admin, usar `ellkan-cli admin create-user --role admin`, que marca el dispositivo como conocido y no depende de email) |
| El puerto 8080 (u otro elegido) ya está ocupado al levantar | Otro proceso/contenedor usando el mismo puerto en el host | Cambiar `ELLKAN_PORT` en `.env` antes de `docker compose up`, o liberar el puerto |
| TLS in-process no arranca, error menciona `ELLKAN_TLS_CERT_FILE`/`KEY_FILE` | Sólo una de las dos variables está seteada, o la ruta no es legible dentro del contenedor (volumen no montado) | Confirmar que las dos estén presentes y que el `volumes:` del compose realmente monte el directorio con los PEM — ver la Opción A de arriba |
| Cliente de navegador rechaza el cert TLS in-process | Cert self-signed sin que el navegador/SO lo tenga como confiable | Esperado con self-signed — para producción real, usar un cert de una CA pública (certbot/Let's Encrypt es el camino más simple), o instalar el cert self-signed como confiable en cada cliente sólo para pruebas |
| Reconstruiste la imagen pero no ves ningún cambio en la app | Casi siempre es el **navegador** sirviendo el bundle JS/CSS viejo desde su propia caché HTTP, no Docker | Ver los comandos paso a paso en [Reconstruir sin caché](#reconstruir-sin-caché-cuando-un-cambio-no-aparece) más abajo |

### Reconstruir sin caché (cuando un cambio no aparece)

Para copiar y pegar, en orden — parar apenas uno de estos resuelva el problema, no hace falta llegar al 3:

**1. Hard refresh del navegador** (la causa más común, ni siquiera es Docker) — `Ctrl+Shift+R` en Windows/Linux, `Cmd+Shift+R` en Mac. O más simple todavía, probar en una ventana privada/incógnito para descartar la caché de una sola vez.

**2. Confirmar que el contenedor realmente se recreó** con la imagen nueva (falta muy común: correr `build` y olvidarse del `up -d` después, que es el paso que efectivamente reemplaza el contenedor corriendo):

```bash
docker compose build ellkan
docker compose up -d ellkan
docker inspect ellkan --format 'Imagen creada: {{.Created}}'
```

La fecha que imprime el último comando tiene que ser de ahora — si es vieja, el `up -d` no se aplicó (revisá que no haya dado error).

**3. Sólo si 1 y 2 no alcanzaron** — forzar un build totalmente limpio, sin ninguna capa cacheada (más lento, recompila todo desde cero, unos varios minutos):

```bash
docker compose build --no-cache ellkan
docker compose up -d ellkan
```

## Requisitos de hardware — estimación razonada, no medida con carga real

**Importante:** esta tabla es un cálculo de ingeniería a partir de lo que el código realmente hace, no el resultado de un load-test contra una instancia real (todavía no se corrió uno). Tratala como punto de partida, no como garantía.

Lo que de verdad determina el techo de concurrencia hoy:

- **El pool de conexiones a Postgres es el default de `sqlx` (10 conexiones), sin override en el código** — es un límite duro de cuántos requests pueden estar tocando la base al mismo tiempo, configurable (`PgPoolOptions::max_connections`) pero hoy fijo en ese valor. Subir este número es la primera palanca real para más concurrencia, antes que agregar CPU/RAM.
- **La derivación de clave (Argon2id) corre 100% client-side** (navegador/CLI del usuario, WASM) — el servidor nunca la computa. Esto es una diferencia real contra un backend "tradicional" con auth por password: el costo de CPU más pesado de un login no le pega al servidor.
- El binario del servidor no tiene runtime pesado (sin JVM, sin Node en producción — imagen final `distroless`, 60.7 MB medidos) — el grueso del consumo de RAM en producción es el propio Postgres (buffer cache), no el proceso de Ellkan.

| | Mínimo | Recomendado |
| --- | --- | --- |
| CPU | 1 vCPU | 2 vCPU |
| RAM | 512 MB | 2 GB |
| Disco | 1 GB + tamaño de los datos | 10 GB + tamaño de los datos |
| Usuarios totales registrados | hasta ~50 | cientos a bajos miles |
| Usuarios concurrentes activos (estimado) | ~10-20 (== tamaño del pool default) | ~50-100 (con `max_connections` subido y Postgres con más RAM para buffer cache) |

Si tu organización va a superar esos órdenes de magnitud, lo correcto es medir contra tu propia carga real (`oha`/`wrk` contra `/auth/challenge` y `/resources` con un dataset representativo) en vez de confiar en esta estimación — subí un issue o correlo vos mismo, la app no tiene ninguna telemetría que se lo reporte a nadie por default.
