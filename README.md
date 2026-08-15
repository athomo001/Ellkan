<p align="center">
  <img src="assets/logo/ellkan-icon-mark-fondo-oscuro.png" alt="Ellkan" width="160">
</p>

<h1 align="center">Ellkan</h1>
<p align="center">Gestor de contraseñas zero-knowledge, self-hosted.</p>
<p align="center"><b>Español</b> (este archivo) · <a href="README.en.md">English</a></p>

**Ellkan** — del mapudungún *elkan*, "esconder, ocultar".

## Qué es Ellkan

Un gestor de contraseñas self-hosted con arquitectura zero-knowledge: el servidor nunca ve tus claves privadas ni tus secretos en claro. Backend en Rust (Axum), cifrado con primitivas modernas (X25519, Ed25519, XChaCha20-Poly1305, Argon2id), frontend web y extensión de navegador comparten el mismo núcleo criptográfico compilado a WebAssembly.

## Stack técnico

### Backend

| Componente | Tecnología |
| --- | --- |
| Lenguaje | Rust (edición 2024) |
| Framework web | Axum (sobre Tokio) |
| Base de datos | PostgreSQL 18+ |
| Acceso a datos | `sqlx`, queries verificadas en tiempo de compilación |
| Autenticación | Firma de nonce con Ed25519 — sin passwords en el servidor |
| Arquitectura | Monolito modular (Controller → Service → Repository) |
| Despliegue | Docker / Docker Compose |

### Frontend y extensión

| Componente | Tecnología |
| --- | --- |
| Frontend web | SvelteKit + TypeScript |
| Extensión de navegador | Manifest V3 (Chrome, Firefox, Safari) |
| Núcleo criptográfico | Compilado a WebAssembly, compartido entre backend, web y extensión |
| Gestor de paquetes | pnpm |
| Testing E2E | Playwright |

### Criptografía

| Primitiva | Uso |
| --- | --- |
| X25519 | Acuerdo de claves (cifrado de extremo a extremo) |
| Ed25519 | Firmas digitales (autenticación) |
| XChaCha20-Poly1305 | Cifrado autenticado (AEAD) de secretos y metadata |
| Argon2id | Derivación de clave maestra desde la passphrase |
| HKDF-SHA256 | Derivación de subclaves con dominio separado por contexto |
| zeroize / secrecy | Borrado y redacción seguros de secretos en memoria |
| subtle | Comparaciones en tiempo constante (mitiga timing attacks) |

## Instalación rápida

Requiere Docker y Docker Compose.

```bash
git clone https://github.com/athomo001/Ellkan.git
cd Ellkan
cp .env.example .env
set -a && source .env && set +a

# Secretos de despliegue — ver secrets/README.md para el detalle de cada uno.
# Usa POSTGRES_USER/POSTGRES_DB del .env recién cargado — si los cambiaste
# ahí arriba, esto arma el DATABASE_URL correcto solo, sin que haya que
# tocarlo a mano en dos lugares.
openssl rand -hex 24 > secrets/postgres_password.txt
openssl rand -base64 32 > secrets/ellkan_secrets_key.txt
echo "postgres://${POSTGRES_USER:-ellkan}:$(cat secrets/postgres_password.txt)@ellkan-db:5432/${POSTGRES_DB:-ellkan}" > secrets/database_url.txt

docker compose up -d
```

La app queda en `http://localhost:${ELLKAN_PORT:-8080}`. El primer admin se crea vía CLI (todavía no hay binarios pre-compilados — se compila desde el código):

```bash
cargo build --release -p ellkan-cli

# DATABASE_URL acá es DISTINTO al de secrets/database_url.txt: ese usa el
# hostname interno de Docker (ellkan-db), que sólo resuelve dentro de la
# red de contenedores — este apunta al puerto que docker-compose expone
# en 127.0.0.1 para que la CLI (corriendo en el host) pueda conectarse.
DATABASE_URL="postgres://${POSTGRES_USER:-ellkan}:$(cat secrets/postgres_password.txt)@localhost:${POSTGRES_PORT:-5433}/${POSTGRES_DB:-ellkan}" \
  ./target/release/ellkan-cli admin create-user \
  --email vos@ejemplo.com --display-name "Tu nombre" --role admin

./target/release/ellkan-cli --server-url "http://localhost:${ELLKAN_PORT:-8080}" login --email vos@ejemplo.com
```

`--role admin` promueve directo (por SQL, sin pasar por HTTP — ninguna ruta HTTP permite auto-asignarse admin) y marca este dispositivo como conocido, así que el `login` de arriba funciona ahí mismo sin esperar ningún email — no hace falta SMTP configurado para arrancar. Una vez adentro, para que las verificaciones de dispositivo de cualquier otro login/usuario lleguen por email de verdad, configurá un relay real en `/admin/smtp`.

Ver [manual/cli.md](manual/cli.md#comandos) para el resto de los comandos.

Por defecto el backend sirve HTTP plano — para TLS (terminado por el propio Ellkan, sin reverse proxy aparte, o con uno), backup/restauración y solución de problemas comunes, ver [manual/instalacion.md](manual/instalacion.md).

### Actualizar / reconstruir tras un cambio

```bash
git pull
docker compose build ellkan
docker compose up -d ellkan
```

Los dos comandos son necesarios: `build` arma la imagen nueva, pero `up -d` es el que efectivamente reemplaza el contenedor corriendo — olvidarse de este segundo paso es el error más común. Si después de esto no ves el cambio, probablemente sea el navegador sirviendo el bundle viejo desde su propia caché (`Ctrl+Shift+R`/`Cmd+Shift+R`, o probar en una ventana privada); si eso tampoco alcanza, ver [Reconstruir sin caché](manual/instalacion.md#reconstruir-sin-caché-cuando-un-cambio-no-aparece) en el manual, con el paso extra para un build sin ninguna capa cacheada.

> **`docker compose build ellkan` puede tardar varios minutos, cada vez** (no sólo la primera) — el build compila el backend en Rust en modo release desde cero (todo el árbol de dependencias, no sólo lo que cambiaste) más el núcleo criptográfico a WebAssembly, sin caché de compilación entre builds. Es esperado, no significa que quedó colgado.

### Requisitos de hardware (estimación, no medida con carga real — detalle y supuestos en [manual/instalacion.md](manual/instalacion.md#requisitos-de-hardware--estimación-razonada-no-medida-con-carga-real))

| | Mínimo | Recomendado |
| --- | --- | --- |
| CPU | 1 vCPU | 2 vCPU |
| RAM | 512 MB | 2 GB |
| Disco | 1 GB + datos | 10 GB + datos |
| Usuarios concurrentes activos | ~10-20 | ~50-100 |

## Documentación

- [manual/funcionalidades.md](manual/funcionalidades.md) — qué hace Ellkan, por área.
- [manual/cli.md](manual/cli.md) — referencia completa de `ellkan-cli`.
- [manual/instalacion.md](manual/instalacion.md) — TLS, backup/restauración, troubleshooting, requisitos de hardware.

## Preguntas frecuentes

**¿El servidor puede ver mis contraseñas?**
No. Todo se cifra y se descifra en tu dispositivo, nunca en el servidor — es como dejarle a alguien una caja fuerte cerrada para guardar: puede guardarla, pero nunca tiene la llave para abrirla ni ver qué hay adentro.

**¿Qué pasa si alguien roba la base de datos del servidor?**
No consigue tus contraseñas — sólo consigue cajas fuertes cerradas. Sin tu contraseña maestra (que nunca se guarda en ningún lado, ni en el servidor), no hay forma de abrirlas.

**¿Cómo protegen mis claves en la memoria de la computadora (RAM) mientras las uso?**
La clave nunca queda "dando vueltas" guardada en la memoria, esperando a que alguien la agarre. Cada vez que hace falta usarla, se reconstruye al toque a partir de tu contraseña, se usa un instante, y se borra inmediatamente — como escribir algo en un papel, usarlo una vez, y romperlo al toque, en vez de dejarlo dando vueltas sobre el escritorio. Tu contraseña maestra se guarda sólo mientras tenés la sesión abierta y nunca toca el disco: si cerrás el navegador o la app, se pierde sola. Lo único que esto no puede evitar es que, si tu computadora ya tiene un virus espiándola, ese virus vea la clave justo en el instante en que la estás usando — ningún gestor de contraseñas puede protegerte de eso, porque ahí el atacante ya está adentro de tu máquina, no del sistema.

## Estado

En desarrollo activo. Backend y frontend web funcionales de punta a punta (registro, login, vault, grupos, MFA, SSO/SCIM/LDAP, auditoría, panel de administración, exportación/backup) — la extensión de navegador todavía no arrancó.

## Licencia

**AGPL-3.0** — ver [LICENSE](LICENSE) (texto oficial en inglés, el único legalmente vinculante) y [LICENSE.es.txt](LICENSE.es.txt) (traducción no oficial al español, sólo de referencia).
