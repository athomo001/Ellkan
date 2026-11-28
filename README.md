<p align="center">
  <img src="assets/logo/ellkan-icon-mark-fondo-oscuro.png" alt="Ellkan" width="160">
</p>

<h1 align="center">Ellkan</h1>
<p align="center">Gestor de contraseñas zero-knowledge, self-hosted.</p>
<p align="center"><b>Español</b> (este archivo) · <a href="README.en.md">English</a></p>

<p align="center">
  <a href="https://www.buymeacoffee.com/athomo"><img alt="Comprame un cafecito" height="60" src="https://img.buymeacoffee.com/button-api/?text=Comprame%20un%20cafecito&emoji=&slug=athomo&button_colour=FFDD00&font_colour=000000&font_family=Cookie&outline_colour=000000&coffee_colour=ffffff"></a>
</p>

**Ellkan** — del mapudungún *elkan*, "esconder, ocultar".

> [!WARNING]
> **Desarrollo en fase beta.** La interfaz, el esquema de datos y la API pueden cambiar entre versiones sin migración automática. Todavía no lo uses como tu único gestor de contraseñas productivo para tu empresa.

## Qué es Ellkan

Un gestor de contraseñas self-hosted con arquitectura zero-knowledge: el servidor nunca ve tus claves privadas ni tus secretos en claro. Backend en Rust (Axum), cifrado con primitivas modernas (X25519, Ed25519, XChaCha20-Poly1305, Argon2id), frontend web y extensión de navegador comparten el mismo núcleo criptográfico compilado a WebAssembly.

## Aplicaciones

| Aplicación | Para qué sirve | Más información |
| --- | --- | --- |
| **Web + servidor** | El servidor Ellkan para un equipo: usuarios, grupos, compartir y administración. Es lo que levanta la [instalación del servidor](#instalar-el-servidor-docker). | [Manual de instalación](manual/instalacion.md) |
| **Escritorio (Windows)** | Gestor de contraseñas para **una sola persona**. Todo queda cifrado en tu PC: funciona sin conexión, sin servidor y sin cuenta en la nube, y opcionalmente se conecta a un servidor Ellkan. Trae instalador MSI, bandeja del sistema con atajo global, botón «Conectar» (SSH, RDP, PostgreSQL, MySQL, MongoDB, FTP, Telnet, VNC), salud de la bóveda, copias de seguridad automáticas y la extensión de navegador incluida. | [Guía de la app de escritorio](app-escritorio/GUIA.md) |
| **Extensión de navegador** | Autocompleta tus credenciales en Chrome, Edge, Brave, Opera y Firefox. Funciona con el servidor o con la app de escritorio, desde la que también se instala. | [Extensión de navegador](extension/README.md) |

## Descargas

Ellkan se distribuye en **dos partes independientes**. Elegí según para quién es:

| | **Uso personal** | **Equipo o empresa** |
| --- | --- | --- |
| Qué es | App de escritorio + extensión de navegador | Servidor Ellkan con su app web |
| Dónde se descarga | [Releases](https://github.com/athomo001/Ellkan/releases/latest) | Imagen Docker `ghcr.io/athomo001/ellkan` |
| Necesita servidor o Docker | No | Sí (Docker) |
| Usuarios | Una persona, todo cifrado en tu PC | Muchos: grupos, compartir, SSO/LDAP/SCIM, auditoría |
| Trae la app de escritorio | Sí | **No**: se descarga aparte, en Releases |

```mermaid
flowchart LR
    subgraph personal["Uso personal · Releases"]
        D["App de escritorio"] --- E1["Extensión"]
    end
    subgraph equipo["Equipo o empresa · imagen Docker"]
        S["Servidor Ellkan + app web"]
    end
    N["Navegador"] --> S
    E2["Extensión"] --> S
    C["ellkan-cli"] -->|administración| S
    D -.->|opcional| S
```

### Uso personal: app de escritorio y extensión (Releases)

Cada versión se publica en **[Releases](https://github.com/athomo001/Ellkan/releases/latest)** (ese enlace lleva siempre a la última). No hace falta Docker ni servidor:

| Archivo | Qué es |
| --- | --- |
| `Ellkan_X.Y.Z_x64_es-ES.msi` | App de escritorio para Windows (instalador, trae la extensión) |
| `Ellkan_X.Y.Z_x64_portable.zip` | La misma app, sin instalar |
| `Ellkan_X.Y.Z_amd64.AppImage` · `Ellkan_X.Y.Z_amd64.deb` · `Ellkan_X.Y.Z_x86_64.rpm` | App de escritorio para Linux (experimental: la [guía](app-escritorio/GUIA.md) todavía la da sólo para Windows) |
| `ellkan-chrome-X.Y.Z.zip` (también `-edge`, `-brave`, `-opera`) | Extensión para navegadores Chromium |
| `ellkan-firefox-X.Y.Z.xpi` | Extensión para Firefox |

Cómo cargar la extensión a mano en cada navegador: [extension/README.md](extension/README.md).

### Equipo o empresa: el servidor (Docker)

El servidor **no está en los archivos de Releases**: se publica como imagen Docker en `ghcr.io/athomo001/ellkan`, con las etiquetas `latest` (la última versión), `X.Y` y `X.Y.Z`. La [instalación del servidor](#instalar-el-servidor-docker) la descarga sola. Trae el servidor y la app web, pero **no la app de escritorio**.

Una vez levantado, cada persona entra desde el navegador. La extensión y, si quiere, la app de escritorio se conectan a ese servidor. Para administrarlo (crear el primer admin, backups) está la CLI, que sí se descarga de Releases: `ellkan-cli_X.Y.Z_windows_x64.exe` · `ellkan-cli_X.Y.Z_linux_x64`.

### Versiones y verificación

Las versiones oficiales salen de `main` y son las marcadas «Latest». Las pre-releases `vX.Y.Z-dev.N` (y la imagen `:dev`) salen de la rama de desarrollo, se reemplazan en cada cambio y no son para producción.

Para verificar una descarga: `sha256sum -c SHA256SUMS.txt --ignore-missing` en Linux, o `Get-FileHash <archivo>` en PowerShell y comparar con su línea de `SHA256SUMS.txt`.

## Capturas

| Vault | Panel de administración | Nuevo recurso |
| --- | --- | --- |
| ![Vault](assets/screenshots/vault.jpg) | ![Administración](assets/screenshots/admin.jpg) | ![Nuevo recurso](assets/screenshots/nuevo-recurso.jpg) |

| Extensión — detalle de un recurso | Extensión — generador de contraseñas |
| --- | --- |
| ![Extensión: detalle](assets/screenshots/extension-popup.png) | ![Extensión: generador](assets/screenshots/extension-generador.png) |

### App de escritorio (Windows)

| Instalador MSI | Primer uso: crear la cuenta |
| --- | --- |
| ![Asistente de instalación de Ellkan](assets/screenshots/escritorio-instalador.png) | ![Pantalla para crear la cuenta local](assets/screenshots/escritorio-crear-cuenta.png) |

| Nuevo recurso: SSH, RDP, bases de datos… | «Conectar» abre el cliente ya listo |
| --- | --- |
| ![Tipos de recurso al crear uno nuevo](assets/screenshots/escritorio-nuevo-recurso.png) | ![Detalle de un recurso SSH con el botón Conectar](assets/screenshots/escritorio-conectar.png) |

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

## Instalar el servidor (Docker)

Son tres pasos. El instalador hace todo lo demás: configura, genera los secretos, levanta el servidor y te abre el navegador en la pantalla para crear tu cuenta de administrador.

### 1. Instalar Docker y Git (una sola vez)

**Windows:** en PowerShell, y después reiniciá la sesión de Windows:

```powershell
winget install --id Docker.DockerDesktop -e
winget install --id Git.Git -e
```

**Linux:** [Docker Engine](https://docs.docker.com/engine/install/) con el plugin de Compose, y `git`. **macOS:** [Docker Desktop](https://docs.docker.com/desktop/setup/install/mac-install/) y `git`.

### 2. Descargar Ellkan

Igual en PowerShell y en bash:

```
git clone https://github.com/athomo001/Ellkan.git
cd Ellkan
```

### 3. Correr el instalador

**Windows (PowerShell):**

```powershell
powershell -ExecutionPolicy Bypass -File .\instalar.ps1
```

**Linux/macOS (bash):**

```bash
bash instalar.sh
```

Al terminar, el navegador se abre en `http://localhost:8080/register` con el **token de instalación** ya puesto (si no se abre, el instalador muestra el link). Completá nombre, email y contraseña: esa primera cuenta queda como administradora.

El token existe para que nadie que llegue a la web antes que vos se quede con el rol de administrador: el servidor lo genera al arrancar, mientras no haya ninguna cuenta, y deja de servir en cuanto creás la tuya.

Si algo falla, el instalador se detiene y dice qué pasó y qué hacer. Se puede correr las veces que haga falta: nunca regenera secretos que ya existen ni toca una base que ya tiene datos.

<details>
<summary><b>Instalación manual, sin el instalador (avanzado)</b></summary>

Lo mismo que hace el instalador, paso por paso.

#### 1. Clonar y cargar el `.env`

**Linux/macOS (bash):**

```bash
git clone https://github.com/athomo001/Ellkan.git
cd Ellkan
cp .env.example .env
set -a && source .env && set +a
```

**Windows (PowerShell):**

```powershell
git clone https://github.com/athomo001/Ellkan.git
cd Ellkan
Copy-Item .env.example .env

# Equivalente a `set -a && source .env`: sólo dura en esta ventana.
Get-Content .env | Where-Object { $_ -match '^\s*[^#\s][^=]*=' } | ForEach-Object {
    $k, $v = $_ -split '=', 2
    Set-Item "env:$($k.Trim())" $v.Trim()
}
```

El `.env` carga sólo en esa terminal: si abrís otra, repetí la última línea (bash) o el bloque `Get-Content` (PowerShell).

#### 2. Generar los secretos

**Sólo la primera vez.** Si ya levantaste el servidor, no los regeneres: la base guarda la contraseña en su volumen y la clave de secretos protege datos ya cifrados. El detalle de cada archivo está en [secrets/README.md](secrets/README.md).

**Linux/macOS (bash):**

```bash
openssl rand -hex 24 > secrets/postgres_password.txt
openssl rand -base64 32 > secrets/ellkan_secrets_key.txt
echo "postgres://${POSTGRES_USER:-ellkan}:$(cat secrets/postgres_password.txt)@ellkan-db:5432/${POSTGRES_DB:-ellkan}" > secrets/database_url.txt
```

**Windows (PowerShell):**

```powershell
# Si esto falla, volvé al paso 1 y corré el bloque de PowerShell (no la línea de bash).
if (-not $env:POSTGRES_USER -or -not $env:POSTGRES_DB -or -not $env:POSTGRES_PORT -or -not $env:ELLKAN_PORT) {
    throw "Falta cargar el .env en esta ventana: corré el bloque Get-Content del paso 1."
}

function Aleatorio([int]$n) {
    $b = New-Object byte[] $n
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
    return ,$b
}

# Equivalente a `openssl rand -hex 24` y `openssl rand -base64 32`.
$pass = -join ((Aleatorio 24) | ForEach-Object { $_.ToString('x2') })
Set-Content secrets/postgres_password.txt $pass -NoNewline -Encoding ascii
Set-Content secrets/ellkan_secrets_key.txt ([Convert]::ToBase64String((Aleatorio 32))) -NoNewline -Encoding ascii
Set-Content secrets/database_url.txt "postgres://$($env:POSTGRES_USER):$pass@ellkan-db:5432/$($env:POSTGRES_DB)" -NoNewline -Encoding ascii
```

En PowerShell, `-NoNewline -Encoding ascii` importa: con `>` o `echo` escribe UTF-16 o agrega un `\r\n`, y ese `\r` queda pegado a la contraseña dentro del contenedor Linux.

#### 3. Levantar

**Linux/macOS (bash):**

```bash
docker compose up -d
```

Descarga la imagen de la versión indicada en `ELLKAN_VERSION` (`.env`; por defecto `latest`, la última oficial) y, si no la encuentra, la compila desde este código (tarda varios minutos). Para compilar siempre desde el código: `docker compose up -d --build`.

La app queda en `http://localhost:8080` (o el puerto de `ELLKAN_PORT`).

> En Windows, si falla con `bind source path does not exist: .../secrets/postgres_password.txt` aunque el archivo existe, Docker Desktop no está viendo el disco: reinicialo (o `wsl --shutdown`) y volvé a levantar. Detalle en [manual/instalacion.md](manual/instalacion.md#problemas-comunes-y-cómo-repararlos).
>
> Los secretos del servidor se copian a un volumen de Docker en cada `docker compose up` (servicio `ellkan-secretos`, que corre y termina: es normal verlo como `Exited (0)`). Si cambiás un archivo de `secrets/`, corré `docker compose up -d` para que tome el valor nuevo. Si venís de una versión anterior y en Windows el contenedor `ellkan` queda en `Restarting` con `no se pudo leer el archivo de ELLKAN_SECRETS_KEY_FILE: Permission denied` (pasaba cuando Docker Desktop se reiniciaba solo), actualizá `docker-compose.yml` y corré `docker compose up -d`.

#### 4. Crear el primer administrador (token de instalación)

La primera cuenta que se crea en una instancia vacía nace **admin**. Para que nadie que llegue a la web antes que vos se quede con ese rol, esa primera cuenta **pide un token de instalación**:

1. **Ver el token.** Mientras no haya ninguna cuenta, el servidor genera uno al azar en cada arranque y lo escribe en su log:

   **Linux/macOS (bash):**

   ```bash
   docker logs ellkan 2>&1 | grep "token de instalación"
   ```

   **Windows (PowerShell):**

   ```powershell
   # Sin la «ó» a propósito: la consola de Windows en español (página 850) no la lee igual que Docker.
   docker logs ellkan 2>&1 | Select-String "token de instalaci"
   ```

2. **Crear la cuenta.** Abrí `http://localhost:8080`, entrá a «Crear cuenta» y pegá el token en el campo «Token de instalación». También podés abrir directo `http://localhost:8080/register#setup=<token>`.

3. Listo: en cuanto existe la primera cuenta, el token deja de servir y no se vuelve a generar. Si reiniciás el contenedor antes de crearla, cambia: volvé a mirar el log.

Para fijar un token propio en vez del generado (`ELLKAN_SETUP_TOKEN` o `ELLKAN_SETUP_TOKEN_FILE`, mínimo 24 caracteres), ver el [manual](manual/instalacion.md#primer-administrador-token-de-instalación).

> [!IMPORTANT]
> **Las versiones hasta la 0.1.70 (incluida) no piden el token:** el primer registro nace admin sin nada. Si la pantalla «Crear cuenta» no muestra el campo del token, estás en una de esas. Creá tu cuenta antes de exponer la instancia a la red, o usá una versión más nueva (`ELLKAN_VERSION=dev` en `.env` y `docker compose pull`, o compilá con `docker compose up -d --build`).

**Alternativa: con la CLI.** No necesita el token porque entra directo a la base. Descargá `ellkan-cli_X.Y.Z_linux_x64` o `ellkan-cli_X.Y.Z_windows_x64.exe` de [Releases](https://github.com/athomo001/Ellkan/releases/latest) y dejalo en esta carpeta como `ellkan-cli` / `ellkan-cli.exe` (o compilalo con `cargo build --release -p ellkan-cli`). El `DATABASE_URL` de acá apunta a `localhost`, no a `ellkan-db` como el de `secrets/`: la CLI corre fuera de la red de Docker.

**Linux/macOS (bash):**

```bash
chmod +x ellkan-cli
DATABASE_URL="postgres://${POSTGRES_USER:-ellkan}:$(cat secrets/postgres_password.txt)@localhost:${POSTGRES_PORT:-5433}/${POSTGRES_DB:-ellkan}" \
  ./ellkan-cli admin create-user --email vos@ejemplo.com --display-name "Tu nombre" --role admin
./ellkan-cli --server-url "http://localhost:${ELLKAN_PORT:-8080}" login --email vos@ejemplo.com
```

**Windows (PowerShell):**

```powershell
# Si esto falla, volvé al paso 1 y corré el bloque de PowerShell (no la línea de bash).
if (-not $env:POSTGRES_USER -or -not $env:POSTGRES_DB -or -not $env:POSTGRES_PORT -or -not $env:ELLKAN_PORT) {
    throw "Falta cargar el .env en esta ventana: corré el bloque Get-Content del paso 1."
}

$pass = (Get-Content secrets/postgres_password.txt -Raw).Trim()
$env:DATABASE_URL = "postgres://$($env:POSTGRES_USER):$pass@localhost:$($env:POSTGRES_PORT)/$($env:POSTGRES_DB)"
.\ellkan-cli.exe admin create-user --email vos@ejemplo.com --display-name "Tu nombre" --role admin
.\ellkan-cli.exe --server-url "http://localhost:$($env:ELLKAN_PORT)" login --email vos@ejemplo.com
```

`--role admin` promueve directo por SQL (ninguna ruta HTTP permite auto-asignarse admin) y marca este dispositivo como conocido, así que el `login` funciona sin esperar ningún email: no hace falta SMTP para arrancar. Una vez adentro, configurá un relay real en `/admin/smtp` para que los códigos de verificación de los demás logins lleguen por email. El resto de los comandos: [manual/cli.md](manual/cli.md#comandos).

</details>

### Después de instalar

Por defecto el servidor sirve HTTP plano. Para TLS (terminado por el propio Ellkan o con un reverse proxy), backup/restauración y solución de problemas comunes, ver [manual/instalacion.md](manual/instalacion.md).

### Actualizar / reconstruir tras un cambio

**Con la imagen publicada** (lo normal). Si fijaste una versión en `ELLKAN_VERSION` (`.env`), cambiala primero por la nueva; con `latest` no hace falta:

```bash
docker compose pull ellkan
docker compose up -d ellkan
```

Las migraciones de la base corren solas al arrancar la versión nueva. Antes de actualizar conviene hacer un backup ([manual/instalacion.md](manual/instalacion.md#backup-y-restauración)).

**Compilando desde el código** (cambios propios, o algo que todavía no salió en una versión):

```bash
git pull
docker compose up -d --build ellkan
```

`--build` arma la imagen con el código de tu carpeta y `up -d` reemplaza el contenedor corriendo. Ojo: esa imagen local queda con el mismo nombre que la publicada, así que un `docker compose pull` posterior la reemplaza por la oficial. Si después de esto no ves el cambio, probablemente sea el navegador sirviendo el bundle viejo desde su propia caché (`Ctrl+Shift+R`/`Cmd+Shift+R`, o probar en una ventana privada); si eso tampoco alcanza, ver [Reconstruir sin caché](manual/instalacion.md#reconstruir-sin-caché-cuando-un-cambio-no-aparece) en el manual, con el paso extra para un build sin ninguna capa cacheada.

> **Compilar (`--build`) puede tardar varios minutos, cada vez** (no sólo la primera) — el build compila el backend en Rust en modo release desde cero (todo el árbol de dependencias, no sólo lo que cambiaste) más el núcleo criptográfico a WebAssembly, sin caché de compilación entre builds. Es esperado, no significa que quedó colgado.

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
- [manual/seguridad.md](manual/seguridad.md) — qué está cifrado y qué no, y qué pasa si alguien intenta sacar los datos (con diagramas).
- [extension/README.md](extension/README.md) — desarrollo, build y empaquetado de la extensión de navegador.

## Preguntas frecuentes

**¿El servidor puede ver mis contraseñas?**
No. Todo se cifra y se descifra en tu dispositivo, nunca en el servidor — es como dejarle a alguien una caja fuerte cerrada para guardar: puede guardarla, pero nunca tiene la llave para abrirla ni ver qué hay adentro.

Lo que el servidor sí ve son datos de la cuenta que necesita para funcionar: tu correo, tu nombre, a qué grupos pertenecés, fechas de creación y modificación, y la IP desde la que te conectás. Hay una excepción elegida a propósito: cuando compartís un secreto con alguien **de afuera** mediante un link externo, quien tenga el link completo puede abrir ese secreto (por eso esos links vencen rápido y pueden llevar una contraseña extra enviada por otro canal).

**¿Qué pasa si alguien roba la base de datos del servidor?**
No consigue tus contraseñas — sólo consigue cajas fuertes cerradas. Sin tu contraseña maestra (que el servidor nunca recibe), no hay forma de abrirlas con lo que hay en la base. Las únicas otras vías son las de recuperación de cuenta, y las activás vos o tu organización: tu propio kit de recuperación (un archivo que sólo vos guardás) o, si tu organización lo configuró, la recuperación aprobada por administradores.

**La recuperación aprobada por administradores.** Si la habilitás en tu cuenta, tu clave privada queda sellada con la clave de recuperación de tu organización. Esa clave la generan y la guardan los administradores en sus propios navegadores: el servidor guarda sólo copias que no puede abrir y exige el número de aprobaciones que fije la organización. Varios administradores juntos pueden restablecer tu acceso, y en ese momento podrían leer tu bóveda; es opt-in por usuario, y si no es aceptable para vos usá el kit de recuperación personal. En instalaciones anteriores, la clave vieja la custodiaba el servidor: cada usuario re-sella su recuperación con la nueva al entrar, y cuando no queda ninguno (o cuando un administrador lo decide) el servidor la borra.

**¿Cómo protegen mis claves en la memoria de la computadora (RAM) mientras las uso?**
Mientras la bóveda está **bloqueada**, en tu equipo no hay ninguna clave en memoria: sólo texto cifrado en disco, y tu contraseña maestra no se guarda en ningún lado (si activás el desbloqueo rápido de la app de escritorio —con un código TOTP o con Windows Hello— queda **cifrada** en ese equipo, con la clave en el llavero del sistema). Mientras está **desbloqueada**, tus claves privadas sí están en memoria, porque hacen falta para descifrar: un programa malicioso que ya esté en tu sesión, o un volcado de memoria en ese momento, podría leerlas. Al bloquear (a mano, por inactividad o al bloquear Windows) se descartan. Ningún gestor de contraseñas puede protegerte de un equipo ya comprometido; por eso conviene bloquear al alejarte. El detalle, con casos de qué pasa si alguien intenta sacar los datos, está en [manual/seguridad.md](manual/seguridad.md).

## Estado

En desarrollo activo. Backend y frontend web funcionales de punta a punta (registro, login, vault, grupos, MFA, SSO/SCIM/LDAP, auditoría, panel de administración, exportación/backup). La extensión de navegador (Chrome, Edge, Brave, Opera, Firefox) también funciona de punta a punta — login, sesión inteligente, bóveda con autofill, generador de contraseñas — ver [extension/README.md](extension/README.md); Safari queda pendiente (exige empaquetado nativo vía Xcode).

## Seguridad

Ellkan no tuvo todavía una auditoría de seguridad externa propia. Si encontrás una vulnerabilidad, por favor no abras un issue público: seguí los pasos de [SECURITY.md](SECURITY.md). Qué datos guarda y a qué servicios se conecta Ellkan: [PRIVACY.md](PRIVACY.md).

## Sin garantía

Ellkan se distribuye **tal cual, sin ninguna garantía**, ni siquiera la implícita de comerciabilidad o de aptitud para un propósito particular, y sin responsabilidad por daños que resulten de su uso (secciones 15 y 16 de la AGPL-3.0). Está en beta: hacé copias de seguridad de tu bóveda.

## Licencia

Copyright (C) 2026 Athan Espinoza.

**AGPL-3.0** — ver [LICENSE](LICENSE) (texto oficial en inglés, el único legalmente vinculante) y [LICENSE.es.txt](LICENSE.es.txt) (traducción no oficial al español, sólo de referencia). Si modificás Ellkan y lo ofrecés a otras personas por red, la AGPL te obliga a ofrecerles el código fuente de tu versión: la app muestra un link «Código fuente» que podés apuntar a tu repositorio con `VITE_ELLKAN_SOURCE_URL` al compilar el frontend.

Las dependencias de terceros y sus licencias están en [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

### Propiedad intelectual y política de marca

El código fuente de este proyecto se distribuye bajo la licencia AGPL-3.0. Sin embargo, los siguientes elementos quedan expresamente excluidos de dicha licencia:

- El nombre **Ellkan**.
- El diseño, imagotipo y archivos visuales contenidos en [`assets/logo/`](assets/logo/), cuya autoría y derechos de autor pertenecen exclusivamente al autor del proyecto.

Se autoriza el uso del nombre y logo exclusivamente con fines descriptivos o de atribución. Cualquier bifurcación (fork), distribución modificada o servicio derivado no oficial debe eliminar toda la identidad visual original y adoptar una denominación propia.
