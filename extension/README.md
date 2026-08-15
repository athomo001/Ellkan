# Extensión de navegador — Ellkan

Autor: Athan Espinoza

Extensión de navegador (Manifest V3) para Chrome, Edge, Brave, Opera, Firefox y Safari. Comparte el mismo núcleo criptográfico (WebAssembly) que el backend y el frontend web — ningún secreto se descifra fuera del dispositivo del usuario.

## Requisitos

- Node.js + [pnpm](https://pnpm.io/)
- `zip` (CLI, para empaquetar) — ya viene instalado en la mayoría de distros Linux/macOS
- Chrome instalado, sólo si querés generar el `.crx` firmado (opcional, el resto del empaquetado no lo necesita)

## Instalación

```bash
pnpm install
```

## Desarrollo

```bash
pnpm check          # tipos (tsc --noEmit)
pnpm check:self      # self-checks sin navegador (node run-self-check.mjs)
node build.mjs       # build sin empaquetar, deja el resultado en dist/ (BROWSER=chrome por default)
BROWSER=firefox node build.mjs
BROWSER=safari node build.mjs
```

Para probar un cambio en un navegador real sin empaquetar: `node build.mjs` y después cargar `dist/` como extensión sin empaquetar (`chrome://extensions` → modo desarrollador → "Cargar descomprimida", o el equivalente en cada navegador).

## Empaquetar para todos los navegadores

```bash
pnpm run package
```

Genera, en la raíz de `extension/`:

| Archivo | Navegador |
|---|---|
| `ellkan-chrome.zip` | Chrome |
| `ellkan-edge.zip` | Edge |
| `ellkan-brave.zip` | Brave |
| `ellkan-opera.zip` | Opera |
| `ellkan-firefox.xpi` | Firefox |
| `ellkan-chrome.crx` | Chrome, firmado (opcional — sólo si Chrome está instalado en la máquina) |

Edge/Brave/Opera son Chromium con Manifest V3 sin ninguna diferencia de manifest respecto a Chrome hoy, así que los 4 `.zip` salen del mismo build — no hay un build separado por cada uno. Safari queda afuera de este script: requiere empaquetado nativo vía Xcode/Swift, no automatizable desde acá.

### Versionamiento automático

`pnpm run package` sube sola el último dígito de la versión (patch) antes de construir nada — se guarda en `package.json` y `manifest.source.json` a la vez (siempre quedan iguales entre sí). No hace falta tocar ningún archivo a mano para esto:

```bash
pnpm run package   # ej. 0.1.34 -> 0.1.35, y ese 0.1.35 es el que queda empaquetado
```

Para cambiar de versión mayor/minor (`x.y`) con reset del patch a `0`, correr esto **antes** de empaquetar:

```bash
node version.mjs --set 0.2   # cualquier versión actual -> 0.2.0
node version.mjs --set 1.0   # cualquier versión actual -> 1.0.0
pnpm run package              # empaqueta con esa versión (y de ahí en más sigue sumando el patch: 0.2.1, 0.2.2, ...)
```

(`pnpm run version:set -- 0.2` hace lo mismo — el `--` es necesario para que pnpm le pase el `0.2` al script en vez de interpretarlo como una opción propia; si te olvidás del `--`, usar `node version.mjs --set 0.2` directo es más simple.)

El `.crx` se firma con `ellkan-chrome.pem` (ya en el repo) — mantiene el mismo ID de extensión entre versiones. Si Chrome no está instalado, el script avisa y sigue sin generar el `.crx` (no es un error duro).

## Estructura

```
extension/
├── manifest.source.json   Manifest único — claves con prefijo __chrome__/__firefox__/__safari__
│                          se resuelven según el navegador de destino al buildear.
├── build.mjs              Resuelve el manifest + arma background.js/content.js/popup/ en dist/.
├── package.mjs            Corre build.mjs por navegador y arma los .zip/.xpi/.crx de arriba —
│                          bumpea la versión sola antes de construir (ver version.mjs).
├── version.mjs            Bump automático del patch, o --set x.y para fijar versión con reset.
│
├── src/
│   ├── background/        Service worker — toda la lógica real corre acá.
│   │   ├── services/        Lógica de negocio (auth-service, vault-service, lock-service,
│   │   │                    autofill-service, sesion-service, wasm.ts).
│   │   ├── controllers/     Validan la forma del pedido y delegan al service correspondiente.
│   │   ├── storage/         Los distintos niveles de storage: cuenta-storage (servidor/email,
│   │   │                    persistente), sesion-storage (claves/sesión, volátil), device-storage
│   │   │                    (token de dispositivo, persistente), metadata-cache (metadata cifrada).
│   │   ├── pagemod.ts        Registra cada conexión (Port) entrante.
│   │   ├── event.ts          Enruta cada mensaje del popup/content script al controller que le toca —
│   │   │                    acá está la tabla completa de rutas (`AUTH_LOGIN`, `VAULT_LISTAR`, etc.).
│   │   ├── port-manager.ts   Anti-spoofing: valida que una reconexión venga del mismo tab/frame.
│   │   └── index.ts          Entry point del service worker.
│   │
│   ├── content/            Content script — se inyecta en cada página visitada (detección de
│   │                       campos de login + autofill). Nunca recibe la bóveda completa, sólo
│   │                       coincidencias ya resueltas por el background.
│   │
│   ├── popup/              Lo que se ve al abrir la extensión (HTML/CSS/TS, sin framework).
│   │   ├── index.html        Todas las "vistas" del popup (login, desbloqueo, MFA, vault, detalle
│   │   │                    de un ítem, formulario de crear/editar, generador de contraseñas, etc.)
│   │   │                    viven en un único HTML, mostradas/ocultadas por clase.
│   │   ├── main.ts            Toda la lógica del popup: qué vista mostrar, manejo de formularios,
│   │   │                    generador de contraseñas, etc.
│   │   ├── styles.css         Estilos del popup.
│   │   ├── conexion.ts         Helpers puros (armar el comando ssh/ftp/etc., resolver favicons).
│   │   ├── passphrase-generator.ts  Generador de frases de paso en español (modo "Frase de paso"
│   │   │                          del generador de contraseñas), 100% local.
│   │   └── diccionario-frases.ts    El diccionario en sí (sólo el array de palabras) — separado
│   │                              para poder agregar/sacar palabras sin tocar la lógica de arriba.
│   │
│   ├── shared/             Código compartido entre content script y popup (cliente de mensajería).
│   └── browser-api.ts      Única capa que llama `chrome.*`/`browser.*` directo — todo lo demás
│                          pasa por acá, para no repetir diferencias entre navegadores en cada archivo.
│
├── self-check.ts           Chequeos sin navegador real (mockea `chrome.runtime.Port`/`chrome.alarms`).
├── self-check-storage.ts   Chequeos de storage con el wasm real (AEAD real, no mockeado).
├── self-check-auth.ts      Chequeos contra un backend real corriendo (login, MFA, vault, autofill) —
│                          no corre por default, sólo con `node run-self-check.mjs self-check-auth.ts`.
└── run-self-check.mjs      Corredor de los self-checks de arriba.
```

## Cómo funciona, en una vuelta rápida

1. **Mensajería**: el popup y el content script hablan con el service worker por un `Port` persistente (`PortClient`/`PortManager`). Cada mensaje trae un `tipo` (ej. `AUTH_LOGIN`, `VAULT_LISTAR`) que `event.ts` enruta a su `Controller`, que valida la forma del pedido y delega al `Service` real.
2. **Storage en capas**: la clave privada nunca se guarda descifrada en ningún lado — se reconstruye cada vez a partir de la passphrase. Las claves ya desenvueltas y el `session_id` viven en storage volátil (se borran solos al cerrar el navegador). Servidor y email, en cambio, quedan guardados de forma permanente tras el primer login y no se vuelven a pedir salvo que el usuario cierre sesión a propósito.
3. **Sesión inteligente**: un timer (`chrome.alarms`, sobrevive a que el navegador duerma el service worker) bloquea la extensión tras 6 horas de inactividad — para desbloquear pide la Contraseña Master y, si la cuenta tiene un segundo factor configurado, un código real. Reiniciar el navegador sólo pide la Contraseña Master. Cerrar sesión a propósito borra todo (servidor, email, y el reconocimiento de este dispositivo) — el próximo inicio es desde cero.
4. **Autofill**: el content script detecta campos de contraseña en la página, pide al background las coincidencias por dominio (el matching corre en el background — la bóveda completa nunca se manda a una página visitada), y ofrece un menú inline (aislado del resto de la página) para completar usuario/contraseña con un clic.
5. **wasm compartido**: el mismo binario WebAssembly del núcleo criptográfico que usa el frontend web se reusa acá tal cual — nunca se reimplementa una segunda vez la criptografía en TypeScript puro.
