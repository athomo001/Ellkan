# Manual de la CLI (`ellkan-cli`)

Cliente de línea de comandos de Ellkan. Todo el cifrado/descifrado corre localmente — el servidor nunca recibe una contraseña en claro, ni siquiera por esta vía.

## Configuración

La CLI resuelve estos valores en orden de precedencia **flag > variable de entorno > perfil guardado > default**:

| Valor | Flag | Variable de entorno | Default |
| --- | --- | --- | --- |
| URL del servidor | `--server-url` | `ELLKAN_SERVER_URL` | `http://127.0.0.1:8080` |
| Certificado de cliente (mTLS) | `--client-cert` | `ELLKAN_CLIENT_CERT` | — (mTLS es opt-in) |
| Clave de cliente (mTLS) | `--client-key` | `ELLKAN_CLIENT_KEY` | — |
| CA bundle adicional | `--ca-bundle` | `ELLKAN_CA_BUNDLE` | — |

`--client-cert` y `--client-key` van siempre juntos — uno sin el otro es un error.

El perfil (email, claves públicas, blob de clave privada cifrada, sesión activa) se guarda en `~/.ellkan/` con permisos `0600`. Para correr varias identidades en la misma máquina, fijá `ELLKAN_CONFIG_DIR` a una ruta distinta por cada una.

La passphrase se puede pasar por variable de entorno (`ELLKAN_PASSPHRASE`) para scripts no interactivos — sin ella, la CLI la pide por prompt oculto.

## Comandos

### `ellkan-cli register --email <email> --display-name <nombre>`
Genera los keypares (X25519 + Ed25519) localmente, cifra la clave privada con la passphrase (pedida por prompt) y registra la cuenta. Guarda el perfil en `~/.ellkan/`.

### `ellkan-cli login --email <email>`
Login por firma de nonce (nunca viaja una contraseña por la red). Si el dispositivo no es conocido todavía, el servidor manda un código de verificación por email — la CLI lo pide por prompt antes de completar el login. Guarda la sesión.

### `ellkan-cli create --name <nombre> --username <usuario> [--uri <uri>] --password <contraseña> [--notes <notas>]`
Crea un recurso login/password. La metadata y el secreto se cifran client-side antes de mandarse.

### `ellkan-cli read <resource-id>`
Descifra y muestra un recurso (metadata + secreto) por su UUID.

### `ellkan-cli list [--filter '<expresión>']`
Lista los recursos visibles, descifrando la metadata localmente. `--filter` acepta una expresión CEL sobre `name`, `username`, `uri`, `id`, `created_by` — ejemplo: `--filter 'name.contains("banco")'`.

### `ellkan-cli share <resource-id> --recipient-email <email> [--level read]`
Comparte un recurso con otro usuario. Sólo funciona sobre recursos `shared_key` (los personales no son compartibles).

### `ellkan-cli exec <resource-id> [--env-var ELLKAN_PASSWORD] -- <comando> [args...]`
Ejecuta un comando externo con la contraseña inyectada como variable de entorno **sólo al subproceso** — nunca queda en el entorno del shell padre ni en el historial. Ejemplo:

```bash
ellkan-cli exec 3fa2... --env-var DB_PASSWORD -- psql -h localhost -U admin mydb
```

### Administración (`ellkan-cli admin <subcomando>`)

La mayoría requiere acceso directo a Postgres (`DATABASE_URL` en el entorno) — son operaciones de infraestructura, no pasan por la API HTTP salvo que se indique lo contrario. **Con despliegue vía `docker-compose.yml`, este `DATABASE_URL` es distinto al de `secrets/database_url.txt`**: ese usa el hostname interno de Docker (`ellkan-db`), que sólo resuelve dentro de la red de contenedores. Desde el host (donde corre la CLI) hay que apuntar al puerto que el compose expone en `127.0.0.1` (`POSTGRES_PORT` del `.env`, default `5433`):

```bash
DATABASE_URL="postgres://ellkan:$(cat secrets/postgres_password.txt)@localhost:5433/ellkan" ellkan-cli admin <subcomando>
```

| Subcomando | Qué hace |
| --- | --- |
| `create-user --email <e> --display-name <n> [--role admin\|user]` | Bootstrap de usuario (registro vía HTTP + rol vía SQL directo si `--role admin`). Con `--role admin` (default `user`), además marca este dispositivo como conocido — el `login` inmediatamente después funciona sin esperar ningún email, no depende de que SMTP ya esté configurado. Es el flujo recomendado para el primer admin de una instancia nueva. |
| `healthcheck` | `GET /healthz` contra el servidor configurado. |
| `datacheck` | Re-valida integridad de datos en modo sólo-lectura (filas huérfanas) — reporta, no toca nada. |
| `cleanup [--fix]` | Sin `--fix`, dry-run de lo que `datacheck` detectaría. Con `--fix`, corrige de verdad — rehúsa correr si no queda ningún admin activo tras la limpieza. |
| `promote-to-admin --user <email>` | Break-glass: promueve un usuario a admin directo por SQL, sin pasar por la API. Para "nos quedamos sin ningún admin activo". |
| `recover-setup --user <email> [--create]` | Recupera/genera el setup inicial de una cuenta a medio onboarding. |
| `send-test-email --to <email>` | Verifica que la cola de notificaciones + el poller de envío SMTP funcionan de punta a punta, sin disparar un flujo de negocio real. |
| `backup create --output <archivo> [--recipient <clave-age>]` | Backup cifrado del sistema completo (streaming, `age`). La clave pública de destino también se puede fijar con `ELLKAN_BACKUP_RECIPIENT`. Sin clave configurada, falla antes de tocar la base de datos. |
| `backup restore --input <archivo> [--identity <clave-privada-age>]` | Restaura desde un backup — exige la clave privada `age` correspondiente, que nunca vive en la instancia. |

## Filtros CEL (`list --filter`)

Soporta expresiones sobre los campos ya descifrados localmente:

```bash
ellkan-cli list --filter 'name.contains("aws")'
ellkan-cli list --filter 'username == "admin@empresa.com"'
```

## mTLS opcional

Si el servidor lo requiere, pasá certificado y clave de cliente (los dos juntos):

```bash
ellkan-cli --client-cert cliente.pem --client-key cliente.key list
```

O fijalos una vez como variables de entorno para no repetirlos en cada llamada.
