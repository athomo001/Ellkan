# Secretos de despliegue

Esta carpeta (menos este archivo) está en `.gitignore` — nunca subas los valores reales a git.

`docker-compose.yml` espera estos tres archivos acá antes de levantar el stack:

| Archivo | Contenido | Cómo generarlo |
| --- | --- | --- |
| `database_url.txt` | Connection string completa de Postgres | `postgres://ellkan:<password>@ellkan-db:5432/ellkan` — usá el mismo `<password>` que pongas en `postgres_password.txt` |
| `postgres_password.txt` | Password del usuario `ellkan` de Postgres | `openssl rand -hex 24` — **nunca base64 acá**: `+`/`/` rompen la URL de conexión (`postgres://user:pass@host:port/db` deja de parsear bien el puerto si el password trae esos caracteres) |
| `ellkan_secrets_key.txt` | Clave maestra del servidor (cifra en reposo el secreto TOTP de login, F-14) — 32 bytes en base64 | `openssl rand -base64 32` — acá sí, no va embebido en ninguna URL |

Ejemplo rápido (usa `POSTGRES_USER`/`POSTGRES_DB` del `.env`, con `ellkan`/`ellkan` como default si no los cambiaste):

```bash
set -a && source .env && set +a
openssl rand -hex 24 > secrets/postgres_password.txt
openssl rand -base64 32 > secrets/ellkan_secrets_key.txt
echo "postgres://${POSTGRES_USER:-ellkan}:$(cat secrets/postgres_password.txt)@ellkan-db:5432/${POSTGRES_DB:-ellkan}" > secrets/database_url.txt
```

**Guardá `ellkan_secrets_key.txt` en un lugar seguro aparte además de acá** — si se pierde, cualquier secreto TOTP ya guardado queda indescifrable (no es recuperable, no es una passphrase de usuario). Rotar este archivo invalida todos los TOTP de login existentes hasta que cada usuario los reconfigure.
