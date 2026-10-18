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

## Compartir externo (F-26): el link no sirve de nada si nadie de afuera puede alcanzarlo

`/admin/policies/external-share` tiene un toggle **"Compartir externo habilitado"** — activarlo sólo prende la lógica del lado del servidor (crear/expirar/quemar el share). No hace que el link sea alcanzable desde afuera de tu red. Si Ellkan vive detrás de VPN/LAN (lo recomendado para un password manager), un destinatario externo que abre `https://tu-ellkan/s/{id}#{clave}` se encuentra con lo mismo que cualquier otra página interna: la conexión no llega, no es un error de la app.

El link necesita dos cosas del lado del servidor para que alguien de afuera lo pueda abrir: el bundle estático de la SPA y el endpoint `GET /external-shares/{id}` — todo lo demás (`/admin`, `/vault`, `/auth/*`) puede seguir cerrado. Tres formas de resolverlo, de más a menos exposición:

1. **Exponer la instancia entera a internet** — la más simple, pero el resto de la superficie (login, admin) queda alcanzable también, protegida sólo por su propia auth/rate-limit.
2. **Reverse proxy con allowlist de rutas** (Caddy/nginx/Traefik) — dejá pasar sólo `/s/*`, los assets estáticos (`/_app/*` o el hash que arme el build) y `GET /external-shares/*`; bloqueá el resto ahí mismo, antes de que llegue a Ellkan.
3. **Túnel saliente** (Cloudflare Tunnel, Tailscale Funnel, `frp`/`chisel` self-hosted) — Ellkan inicia la conexión hacia afuera, sin abrir ningún puerto entrante en tu firewall. Combinable con la allowlist del punto 2 en el proxy que recibe del túnel.

Si tu instancia va a quedar completamente cerrada y no vas a implementar ninguna de las tres, dejá el toggle **apagado** — mostrarlo prendido sin que el link funcione es peor que no tener el feature.

## Backup y restauración

Comandos completos en [manual/cli.md](cli.md#comandos) (`ellkan-cli admin backup create`/`backup restore`). Puntos operativos que no están ahí:

- **El backup es del sistema completo** (todas las tablas vía `pg_dump` en streaming, cifrado con [`age`](https://github.com/FiloSottile/age) antes de tocar disco — nunca queda un dump en claro) — no hay backup parcial (sólo-vault, sólo-usuarios, etc.) en v1.
- **La clave privada `age` de restauración no vive en la instancia** — guardala aparte (gestor de secretos, un lugar frío) desde el mismo momento en que generás el par de claves. Perder esa clave privada hace el backup irrecuperable — no hay puerta trasera, es cifrado real.
- **Restaurar es destructivo sobre la base destino** — pensalo como "reemplazar", no "fusionar". El flujo recomendado para migrar de servidor: levantar el `docker-compose.yml` nuevo con la base vacía (migraciones corren solas al arrancar), después `backup restore` apuntando su `DATABASE_URL` a esa base recién creada, antes de exponerla a usuarios reales.
- **Restaurar no reimporta `ellkan_secrets_key.txt`** — ese archivo es del *servidor* (cifra en reposo el TOTP de login), no de los datos. Si el backup se restaura en una instancia nueva con una `ellkan_secrets_key` distinta a la original, todo TOTP de login ya configurado queda indescifrable — cada usuario tiene que reconfigurar su TOTP. Para evitar esto, restaurá también el `ellkan_secrets_key.txt` original junto con los datos, guardado en el mismo lugar frío que la clave `age`.

## Ver qué está pasando (logs)

```bash
docker logs -f ellkan                      # en vivo
docker logs ellkan --since 10m | grep -E "WARN|ERROR"   # sólo problemas recientes
```

Sin configurar nada, el servidor registra lo que sale mal: arranque, solicitudes rechazadas (4xx), límites de solicitudes (429) y fallos del servidor (5xx). Cada línea trae método, ruta, IP de origen, `actor_id` (si había sesión), status y latencia. Nunca headers, cuerpo ni secretos.

| Nivel | Qué significa |
| --- | --- |
| `ERROR` … `solicitud falló en el servidor` | 5xx: bug o problema de base de datos. Revisar la línea anterior para el detalle |
| `WARN` … `límite de solicitudes por IP agotado` (`limite="ip"`) | Muchas solicitudes **sin sesión** desde la misma IP (10/s, ráfaga 250): intentos de login, registro, recuperación, enlaces públicos. Posible abuso |
| `WARN` … `límite de solicitudes por usuario agotado` (`limite="usuario"`) | Un mismo usuario con sesión pidiendo demasiado rápido (20/s, ráfaga 300). Los usuarios con sesión no comparten cupo aunque estén detrás de la misma IP |
| `INFO` … `solicitud rechazada` | 4xx normal: sesión vencida, sin permiso, dato inválido |

Para ver también cada solicitud exitosa, definí `RUST_LOG=ellkan_backend=debug` en el `environment:` del servicio `ellkan` y recreá el contenedor (`docker compose up -d ellkan`). `RUST_LOG` reemplaza al filtro por defecto (`warn,ellkan_backend=info`).

En la web y en la app de escritorio, el error real de una pantalla que no carga queda en la consola de DevTools (F12 → Console).

## Problemas comunes y cómo repararlos

| Síntoma | Causa | Reparación |
| --- | --- | --- |
| El contenedor `ellkan` no arranca, log menciona una migración | Migraciones corren automáticamente al boot (forward-only, sin rollback) — una migración que falla a mitad de camino puede dejar el schema en un estado intermedio | Revisá el log completo del contenedor (`docker logs ellkan`) para identificar cuál migración falló; si es un `CHECK`/`UNIQUE` violado por datos preexistentes de una versión vieja, hace falta limpiar esos datos a mano antes de reintentar — no hay downgrade automático |
| `ellkan-cli` no puede conectar a Postgres aunque el contenedor esté sano | `DATABASE_URL` de la CLI (host) usa `localhost:${POSTGRES_PORT}`, **no** el mismo valor que `secrets/database_url.txt` (que usa el hostname interno `ellkan-db`, sólo resuelve dentro de la red de Docker) | Usar el `DATABASE_URL` armado con `localhost`, ver el snippet en [manual/cli.md](cli.md#administración-ellkan-cli-admin-subcomando) |
| `ellkan-cli`/`docker` no ven el daemon aunque Docker Desktop esté corriendo (Linux con Docker Desktop instalado) | El contexto de Docker activo puede seguir apuntando al socket de Docker Desktop en vez del daemon real del sistema — nos pasó en desarrollo | `docker context ls` para confirmar, `docker context use default` para volver al daemon real |
| `docker compose up` falla con el password de Postgres / la URL no parsea bien el puerto | `postgres_password.txt` generado con caracteres que rompen una URL (`+`, `/` — típico si se generó con `base64` en vez de `hex`) | Regenerar con `openssl rand -hex 24` (nunca `base64`) para ese archivo puntual — ver [secrets/README.md](../secrets/README.md) |
| `docker compose up` falla en Windows con `invalid mount config for type "bind": bind source path does not exist: /run/desktop/mnt/host/e/.../secrets/postgres_password.txt`, aunque el archivo existe | Docker Desktop quedó con una vista vieja del disco (típico si el disco se montó o cambió después de que Docker arrancó): ve la carpeta `secrets/` **vacía**. Para confirmarlo: `docker run --rm -v "E:/ruta/a/Ellkan/secrets:/s" alpine ls /s` no lista nada | Reiniciar Docker Desktop (ícono de la bandeja → Restart). Si no alcanza, `wsl --shutdown` y volver a abrir Docker Desktop. Repetir el `docker run ... ls /s`: tiene que listar los tres archivos. Si sigue vacío, revisar que el disco esté habilitado en Docker Desktop → **Settings → Resources → File sharing / WSL integration** |
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

- **El pool de conexiones a Postgres es de 30 por defecto** (antes el default de `sqlx`, 10). Es el límite de cuántos requests pueden estar tocando la base al mismo tiempo. Se cambia con la variable `ELLKAN_DB_MAX_CONNECTIONS` en el `environment:` del servicio `ellkan`; dejarlo por debajo del `max_connections` de Postgres (100 por defecto). Medido (2026-10-17, build de debug): 25 usuarios importando 200 claves cada uno al mismo tiempo, desde la misma IP, crearon las 5.000 en 34 s sin ningún rechazo.
- **La derivación de clave (Argon2id) corre 100% client-side** (navegador/CLI del usuario, WASM) — el servidor nunca la computa. Esto es una diferencia real contra un backend "tradicional" con auth por password: el costo de CPU más pesado de un login no le pega al servidor.
- El binario del servidor no tiene runtime pesado (sin JVM, sin Node en producción — imagen final `distroless`, 60.7 MB medidos) — el grueso del consumo de RAM en producción es el propio Postgres (buffer cache), no el proceso de Ellkan.

| | Mínimo | Recomendado |
| --- | --- | --- |
| CPU | 1 vCPU | 2 vCPU |
| RAM | 512 MB | 2 GB |
| Disco | 1 GB + tamaño de los datos | 10 GB + tamaño de los datos |
| Usuarios totales registrados | hasta ~50 | cientos a bajos miles |
| Usuarios concurrentes activos | ~25 importando a la vez (medido, pool de 30) | ~50-100 (con `ELLKAN_DB_MAX_CONNECTIONS` subido y Postgres con más RAM para buffer cache) |

Si tu organización va a superar esos órdenes de magnitud, lo correcto es medir contra tu propia carga real (`oha`/`wrk` contra `/auth/challenge` y `/resources` con un dataset representativo) en vez de confiar en esta estimación — subí un issue o correlo vos mismo, la app no tiene ninguna telemetría que se lo reporte a nadie por default.
