# Changelog

Autor: Athan Espinoza

Registro de cambios de Ellkan. Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/), con una salvedad: el número de versión de cada entrada es un contador propio de este archivo, uno por fase de implementación cerrada — **no** corresponde a la versión real del paquete en `Cargo.toml` (que sigue fija en `0.1.0` hasta el primer release etiquetado de v1) ni a la de `frontend/package.json` (fija en `0.0.1`, mismo criterio). **Excepción real: la extensión de navegador** (`extension/package.json`/`manifest.source.json`) sí tiene que moverse — a diferencia del backend/frontend, que nunca se "instalan" como paquete versionado por el usuario, la extensión es un artefacto que el usuario instala y actualiza de verdad (`.crx`/`.xpi`), así que necesita un número de versión real que avance con cada release. No hay una correspondencia 1:1 fija entre ambos contadores — sólo referenciar la fecha/entrada de este archivo si hace falta ubicar qué versión de la extensión trae qué cambios.

## [0.1.51] - 2026-09-21

### Instalación limpia: primer uso, desinstalar con la opción de borrar los datos, y el llavero de Windows que nunca guardaba nada

- **Al probar el MSI se vio que reinstalar caía en el login, sin «crear cuenta».** Causa: el instalador conserva `%APPDATA%\Ellkan` (a propósito, `[0.1.50]`), así que la bóveda de las pruebas seguía ahí y la app la encontró. Una instalación en un equipo sin datos no tenía ese problema, pero tampoco iba directo a crear la cuenta: abría el login (con un enlace «Regístrate»). Ahora, si no existe ninguna cuenta local, el login redirige solo a `/register` (`replaceState`, para que «atrás» no vuelva). Verificado en la prueba de punta a punta (perfil limpio → abre en `/register`).
- **Desinstalar ahora ofrece borrar los datos.** Si el desinstalador tiene interfaz (Configuración → Aplicaciones, o «Desinstalar Ellkan» del menú Inicio), la app pregunta dos veces, con «No» por defecto, si además de quitar el programa quiere borrar la bóveda, los ajustes, las copias de seguridad, los datos de la ventana (`%LOCALAPPDATA%\com.ellkan.desktop`), el `desktop.json` y las claves del llavero. La desinstalación silenciosa (`/qn`) **nunca** borra ni pregunta. Se decidió preguntar en vez de borrar siempre porque la bóveda es la única copia de las contraseñas y borrarla no se deshace. Lo hace `ellkan-desktop.exe --limpiar-sistema --preguntar-datos` (`--borrar-datos` sin preguntar, para scripts); dos acciones de `installer/limpieza.wxs` según `UILevel`. `borrar_carpeta_de_datos` sólo acepta carpetas llamadas `Ellkan`, `ellkan-datos` o `com.ellkan.desktop`, a tres o más niveles de la raíz, y no toca lo demás de `~/.ellkan` (lo comparte la CLI). 3 tests + 5 pasos nuevos en la prueba de punta a punta (que se conserva sin la opción, que se borra con ella, y que `perfil.json` de la CLI sobrevive). **Sin verificar**: el cuadro de diálogo dentro del desinstalador real (el flujo lo prueba el usuario).
- **Bug real encontrado de paso: el desbloqueo con el llavero de Windows (F-50) nunca funcionó.** `keyring` 3 no trae ningún almacén del sistema por defecto y estaba compilado sin `windows-native`, así que usaba un almacén de prueba en memoria: `guardar_envoltura_llavero` no guardaba nada (ni cada `Entry` veía lo de la anterior). Se habilitó `windows-native` y hay una prueba contra el Administrador de credenciales real (guardar, leer desde otra entrada, borrar). Quien haya activado «Windows Hello» en Ajustes → Seguridad tiene que volver a activarlo: lo anterior no se guardó.
- **README principal**: sección «Aplicaciones» (web + servidor, escritorio para Windows y extensión de navegador) con enlaces a la guía de escritorio y al README de la extensión, en español y en inglés.

## [0.1.50] - 2026-09-21

### Instalador MSI con desinstalador

- **`Ellkan_0.1.0_x64_es-ES.msi`** (6,6 MB, sin firmar) en `app-escritorio/windows/binarios/`, generado con `build-windows.ps1 -Msi`. Se instala en `C:\Program Files\Ellkan` (pide administrador), con accesos en el menú Inicio y el escritorio, y se desinstala desde Configuración → Aplicaciones o con «Desinstalar Ellkan» del menú Inicio. Trae `ellkan-desktop.exe` y `ellkan_askpass.exe` (el ayudante de SSH, que Tauri incluye solo). La versión sale de `tauri.conf.json`.
- **Desinstalar limpia lo que la app deja fuera de su carpeta** y no toca los datos. Al desinstalar (no al actualizar) corre `ellkan-desktop.exe --limpiar-sistema`, que borra el inicio con Windows y el esquema `ellkan://` de `HKCU`, y sale sin abrir la app. `%APPDATA%\Ellkan` (bóveda, ajustes, copias), el log y la carpeta de la extensión se conservan a propósito: una desinstalación no debe borrar la única copia de tus contraseñas.
- **Cierra Ellkan al instalar, actualizar o desinstalar.** La app vive en la bandeja y casi siempre está abierta; un `taskkill` antes de `InstallValidate` evita el «archivos en uso / reiniciar». Se termina el proceso en vez de pedirle que se cierre porque la ventana preguntaría «¿cerrar o dejar en la bandeja?». No se pierde nada: la bóveda es SQLite. Ojo: mata también el `.exe` de `windows\binarios` si está abierto.
- **Lo propio está en dos archivos**: `src-tauri/tauri.msi.conf.json` (sólo se aplica con `tauri build --config`, así que las compilaciones normales no cambian) y `src-tauri/installer/limpieza.wxs`. La plantilla de Tauri ya traía el acceso directo de desinstalar y el ayudante de SSH; se traducen sus textos (que vienen en inglés) dentro del MSI ya armado.
- **Gráfica del asistente con la marca.** Reemplaza la imagen por defecto de WiX (un disco con un ancla): el panel de bienvenida y de cierre lleva el escudo de Ellkan y un resumen de una línea de qué es («Gestor de contraseñas: tus contraseñas quedan cifradas en este equipo, sin nube ni servidor, y solo tú puedes abrirlas»), y el resto de pantallas un banner con el escudo sobre una placa de color de marca (el logo tiene partes oscuras que se pierden sobre blanco). Las dos imágenes (BMP de 493×312 y 493×58, medidas exactas de WiX) las genera `src-tauri/installer/generar-imagenes.ps1` con System.Drawing, sin dependencias, y se declaran en `tauri.msi.conf.json` (`dialogImagePath`, `bannerPath`).
- **`crate-type` del shell reducido a `rlib`.** Con `staticlib` y `cdylib` (que sólo hacen falta en móvil) cada compilación generaba una `.lib` de 266 MB, y el empaquetador metía la `.dll` en el instalador sin que nadie la use.
- **Verificado**: contenido del MSI (tablas `File`, `Shortcut`, `CustomAction`, `InstallExecuteSequence`, actualización con el mismo `UpgradeCode`), instalación administrativa a una carpeta temporal (extrae exactamente los dos `.exe`), y `--limpiar-sistema` en la prueba de punta a punta (71/71 sobre el ejecutable **release**). **Sin verificar**: instalar y desinstalar de verdad (las herramientas de esta sesión no dejan escribir en `C:\Program Files`), en particular que el desinstalador borre el registro del usuario que desinstala y que un MSI de una versión mayor actualice sobre el anterior.

## [0.1.49] - 2026-09-20

### Revisión completa de la app de escritorio: seguridad del backend local, copias, inicio con Windows, enlaces, salud de la bóveda y "Conectar" para RDP y bases de datos

Tras revisar el plan (`spec/05`) contra el código se cerró todo lo pendiente de Windows que se podía cerrar. Linux/macOS quedan fuera (pedido explícito). Prueba automática de la app real: **68/68**; 113 tests de escritorio en verde (16 archivos) + 3 del shell; `clippy -D warnings` limpio.

- **Seguridad del backend local (marcado `[x]` en el plan sin serlo).** El router de escritorio usaba CORS abierto a todos los orígenes y no validaba `Origin` ni `Host`: cualquier página web abierta en el navegador podía llamar a `127.0.0.1:<puerto>` y leer las rutas públicas de login; con DNS rebinding hasta parecía "mismo origen". Ahora (`backend-desktop/origen.rs`): el `Origin`, si viene, tiene que ser la app (`http://tauri.localhost`), una extensión de navegador o —sólo en debug— el servidor de Vite; el `Host` tiene que ser loopback. Sin `Origin` (el helper de SSH, `curl`, la CLI) se atiende. Una página ajena recibe 403 y ningún CORS. 12 tests + verificado por HTTP real contra el `.exe`.
- **`/auth/logout` en escritorio.** No estaba montado: "cerrar sesión" sólo olvidaba el token del lado del cliente y la sesión seguía válida hasta vencer. Ahora la revoca.
- **Bug real de concurrencia encontrado por los tests nuevos (`sync_concurrencia_sqlite.rs`).** `updated_at` hace de versión para `If-Match` con precisión de milisegundos: dos ediciones del mismo recurso dentro del mismo milisegundo daban la misma versión y la segunda **pisaba a la primera sin conflicto** (pérdida silenciosa de un cambio). La versión nueva es ahora siempre estrictamente posterior a la anterior (`nueva_version` en `repositories/resources.rs`). Es el mismo síntoma que ya se había esquivado con un `sleep` en un test. El servidor Postgres (microsegundos) no se tocó.
- **Copias de seguridad (F-53).** `ellkan.db` es la única copia de los datos. Antes de aplicar migraciones pendientes se guarda una copia consistente (`VACUUM INTO`, sigue cifrada) en `<datadir>/backups/`, se conservan las últimas 5, y si la copia falla no se migra. Ajustes → Escritorio → "Copias de seguridad": lista, "Crear copia ahora" y "Mostrar carpeta". 7 tests, incluido el arranque real con una migración pendiente. **Pendiente de F-53**: el actualizador firmado de Tauri (necesita una clave de firma y un servidor de actualizaciones que decide el usuario).
- **Inicio con la sesión de Windows y modo portable (F-54).** Ajustes → Escritorio → "Inicio y sistema": abrir al iniciar sesión (clave `HKCU\...\Run` con `--minimizado`: arranca sólo en la bandeja; se lee del registro, no de un flag, y si la app se movió cuenta como desactivado). `--portable` (o un archivo `ellkan-portable.txt` junto al `.exe`): la bóveda, `desktop.json` y la extensión quedan junto al ejecutable y no se escribe nada en `%APPDATA%`.
- **Enlaces `ellkan://` (deep links).** Opt-in en Ajustes. `ellkan://abrir`, `ellkan://item/<uuid>` (abre ese recurso en la bóveda). Entrada no confiable: sólo esas formas, con el id validado; el resultado es siempre una ruta interna `/vault...`, nunca ejecuta nada ni revela nada por sí mismo. Llegan a la instancia ya abierta (instancia única). 5 tests + E2E (un enlace malformado no navega).
- **Bloquear la bóveda al bloquearse la pantalla de Windows (F-52).** Con el aviso documentado de Windows (`WM_WTSSESSION_CHANGE`, `WTS_SESSION_LOCK`) enganchado a la ventana, no consultando el estado: se probó una consulta (`WTSSessionInfoEx`) y **devuelve `0` con la sesión desbloqueada en Windows 11, al revés de lo documentado**, así que se descartó. Bloquear la pantalla de verdad sacaría al usuario de su sesión, por eso la prueba simula el mismo mensaje: la bóveda se bloquea, se desbloquea con la contraseña, y con la opción apagada no se bloquea. Activado por defecto (opción segura). **Sin probar**: que Windows mande de verdad ese mensaje al bloquear la pantalla (es su comportamiento documentado).
- **Avisos.** La ventanita que avisa que la app quedó en la bandeja (`[0.1.45]`) ahora es un aviso genérico (`static/aviso.html`) y se usa además cuando el puerto fijo estaba ocupado y se usó otro sólo para esa sesión (F-52: antes fallaba en silencio). No son notificaciones toast del SO: un `.exe` portable sin identificador registrado puede no mostrarlas sin ningún error.
- **Salud de la bóveda (F-57).** Nuevo "Salud" en el menú: contraseñas **débiles** (zxcvbn), **repetidas** (huella SHA-256 local; marca a todos los recursos del grupo), **viejas** (umbral elegido por el usuario; por defecto ninguna, NIST SP 800-63B) y **filtradas** (HIBP Pwned Passwords k-anonymous, opt-in: sólo el prefijo de 5 caracteres del SHA-1 con `Add-Padding`, y sólo al apretar el botón). Todo en el cliente; cada hallazgo enlaza a "Editar" (`/vault?abrir=<id>`). Lógica pura en `lib/salud/` con 15 checks ejecutables (`node --experimental-strip-types frontend/scripts/check-salud.mjs`) y probada en la app real creando recursos por la interfaz. **Sin probar**: la consulta real a HIBP y, en la versión web, si la CSP del backend la bloquea.
- **"Conectar" para RDP y bases de datos (F-49, fase 3.3).** Tipos nuevos `rdp`, `postgresql`, `mysql`, `mongodb` (migración SQLite 0008 **y migración Postgres 0048**, para que sincronizar no falle con "tipo desconocido"; la de Postgres no se pudo ejecutar acá — no hay Docker). Qué se lanza lo decide un plan puro y testeado (`backend-desktop/conectar.rs`, 13 tests): `mstsc /v:host:puerto` con la contraseña en una **credencial `TERMSRV/<host>` de Windows con persistencia de sesión** (API directa, no `cmdkey`, que la pondría en la línea de comandos), borrada a los 20 s; `psql`/`mysql` con `PGPASSWORD`/`MYSQL_PWD` sólo en el entorno del hijo; `mongosh` y ftp/telnet/vnc sin forma de recibirla: portapapeles con auto-limpieza. Probado contra el Administrador de credenciales real (escribir, leer con acentos y euro, borrar). **Sin probar**: lanzar `mstsc`/`psql`/`mysql`/`mongosh` de verdad. **Arreglo de seguridad de paso**: `host` y `usuario` vienen de datos que pueden importarse (F-27) y se pasaban tal cual a `ssh`; un host `-oProxyCommand=...` se leería como opción y ejecutaría un comando. Ahora se validan (sin `-` inicial, sin caracteres de shell) antes de armar nada. Extensión **0.3.1 -> 0.3.2** (muestra el comando de conexión de los tipos nuevos).
- **Sin ventana de consola, log en release.** El log a archivo (`Ellkan.log`, rotación de 3 x 2 MB) ahora también existe en release (sólo avisos y errores); antes sólo el build de debug escribía log.
- **Tests de sync con concurrencia real** (4): dos y seis clientes editando a la vez —gana uno, el resto recibe conflicto—, el que pierde reintenta sobre la versión nueva sin perder su cambio, y desvincular deja la bóveda funcionando en local.

**Lo que NO se hizo, y por qué:**

- **Punto 10** (vincular el usuario local a una cuenta que YA existe en el servidor, con otras claves). Al leer el motor de sync apareció un problema de diseño que hay que decidir antes: el AAD con el que se cifra cada recurso incluye `created_by` (el UUID del usuario en SU base), pero el UUID local y el del servidor son distintos y el pull vuelve a crear el recurso con el `created_by` local — así que un recurso cifrado por otro cliente **no se puede descifrar** localmente (y viceversa). Vincular con otras claves lo agrava (habría que re-cifrar todo con otro AAD). Necesita una decisión (AAD estable por cuenta, o UUID de usuario compartido) y un servidor real para probarlo; sin eso arriesgaría la única copia de la bóveda. Detalle en `docs/pendientesVerificacionReal.md`.
- **F-56 (emparejar la extensión con native messaging) y F-55 (agente SSH, git credential helper)**: cada una es un proyecto propio (host nativo + registro en los navegadores + cambio de permisos de la extensión; protocolo del agente SSH sobre un named pipe). La CLI ya tiene `exec` (secreto al entorno del hijo) y la extensión ya trae la dirección del backend (`[0.1.46]`).
- **Actualizador firmado, instalador MSI/NSIS firmado, publicación en las tiendas de extensiones**: dependen de un certificado/clave de firma, de un servidor de actualizaciones y de cuentas de desarrollador del usuario.

## [0.1.48] - 2026-09-20

### "¿Por qué siguen deshabilitados sólo-memoria y sólo-nombres?" — el aviso culpaba a internet, y el motivo es que no hay servidor vinculado

- Sin un servidor Ellkan vinculado (Ajustes → Modo conectado) esos dos modos no tienen de dónde bajar las contraseñas, así que están deshabilitados **a propósito**; tener internet no cambia nada. Pero cada tarjeta decía en ámbar "Este modo necesita conexión a internet para ver contraseñas", que apunta a la causa equivocada (el usuario, con internet, no entendía por qué seguían apagadas). Ahora dice "Se habilita al conectar la bóveda a un servidor Ellkan (tarjeta "Modo conectado", arriba)" y, bajo la explicación, hay un botón **"Ir a conectar un servidor"** que lleva a esa tarjeta (`id="modo-conectado"`). Con servidor vinculado se mantiene el estado real de la conexión (✓/⚠) de la entrada `[0.1.46]`. Se quitó la clave i18n `persistenciaRequiereOnline`, que ya no se usa.

## [0.1.47] - 2026-09-20

### La barra de título se iba con el contenido y no se podía mover la ventana

- **Bug:** la barra de título propia (`TitleBar.svelte`) era `position: sticky`, y un sticky sólo se queda pegado dentro de su contenedor — acá el `body`, que mide `100%` de la ventana (`base.css`). Al bajar por una página más larga que la ventana, la barra se iba con el contenido; como es lo único de donde se arrastra la ventana (`data-tauri-drag-region`), no había cómo moverla. Ahora es `position: fixed` y un espaciador de 36 px en el flujo le reserva el lugar (los layouts que restan `--titlebar-h` siguen igual). El panel de detalle del Vault, que también es sticky, ahora se pega debajo de la barra en vez de meterse 4 px detrás.
- **Verificado** en un Chromium headless aislado (mismo motor que WebView2; perfil temporal, sin tocar el navegador del usuario): con una página larga y el scroll al final, la barra queda en `top: 0` y el punto (300, 10) sigue siendo de la barra; con el CSS anterior (`sticky`) daba `top: -2336` y no era arrastrable. El mismo chequeo quedó como paso nuevo de `e2e-escritorio.mjs` (corre contra la app real cuando no haya otra instancia abierta: es de instancia única).

## [0.1.46] - 2026-09-20

### Sin ventana de consola, la extensión ya sabe el puerto y el estado de la conexión se comprueba de verdad

- **Ventana de consola al abrir el `.exe`.** El `.exe` que se prueba a mano (`windows\binarios`) es un build de debug, y `main.rs` sólo ocultaba la consola en release: al abrirlo aparecía una ventana negra con el log (`backend local escuchando en 127.0.0.1:…`, el aviso de SMTP no configurado). Ahora `windows_subsystem = "windows"` vale también en debug (verificado: subsistema 2 en el PE). El log no se pierde: `tauri-plugin-log` lo sigue escribiendo en `Ellkan.log` (carpeta de logs de la app). Contrapartida para desarrollo: `cargo run` desde una terminal ya no imprime el log ahí; se lee del archivo. `ellkan_askpass.exe` (F-49) no se toca: ese sí necesita consola para entregarle la clave a `ssh`.
- **La extensión pedía "el puerto" y el usuario no tiene cómo saberlo.** El login de la extensión trae `http://localhost:8080` (el servidor multiusuario), pero el backend de escritorio escucha en un puerto que la app elige sola (rango dinámico, persistido). Ahora, al instalar la extensión y en cada arranque, la app deja `ellkan-escritorio.json` (`{"server_url":"http://127.0.0.1:<puerto>"}`) dentro de la carpeta de la extensión (`ellkan_backend::desktop::extension::escribir_conexion`; `instalar` no lo borra como obsoleto). El popup lo lee (`fetch` a su propio paquete), pone esa dirección en "Servidor" y muestra "Ellkan de escritorio detectado en este equipo: la dirección ya viene puesta". Sólo acepta `http://127.0.0.1:<puerto>` o `localhost`: el archivo no puede mandar el login a un servidor de afuera. Ajustes → Escritorio → Extensión también muestra esa dirección en la guía. Extensión **0.3.0 → 0.3.1** (sin subir la versión, `esta_al_dia` habría dado por buena la carpeta ya extraída y nunca habría llegado el popup nuevo). 3 tests nuevos (`desktop_extension.rs`, ya son 19).
- **Ajustes → Modo conectado → "Persistencia de secretos": el aviso "necesita conexión a internet" era fijo aunque hubiera conexión.** Con la bóveda conectada, cada tarjeta de sólo-memoria/sólo-nombres ahora muestra el estado real: "✓ Hay conexión con el servidor ahora", "⚠ Sin conexión con el servidor ahora: no podrías ver contraseñas hasta reconectar" o "Comprobando…". Se mide con un `GET /healthz` al servidor vinculado (`lib/sync/conectividad.ts`, `mode: 'no-cors'` porque sólo importa si hay camino hasta el servidor — un servidor vivo sin CORS para este origen no debe verse como caído), con tope de 5 s, y se repite al cambiar la red (`online`/`offline`) y cada 30 s. Sin servidor vinculado se mantiene el aviso fijo (no hay nada que comprobar y las tarjetas están deshabilitadas).
- **Sin probar con clicks reales**: la lectura de `ellkan-escritorio.json` desde el popup dentro de un navegador real (hace falta cargar la extensión a mano) y las tarjetas de conexión con un servidor remoto real (la prueba automática no tiene uno). Sí verificado: el archivo queda escrito con el puerto correcto, el popup embebido trae el aviso, y la sonda de alcance contra un servidor abierto / cerrado / colgado. Prueba automática de la app real: 30/30.

## [0.1.45] - 2026-09-20

### Al dejar la app en la bandeja, un aviso lo dice

- **Pedido del usuario:** al tocar la "X" y quedar la app en la bandeja, avisarle, para evitar el malentendido de "la cerré y no se cerró". Ahora, cada vez que la ventana principal se esconde en la bandeja (elegir *Dejar en la bandeja* en el diálogo, o tener la preferencia fija en "Minimizar a la bandeja"), aparece una ventanita sin bordes en la esquina inferior derecha del área útil: "Ellkan sigue abierto — quedó en la bandeja del sistema, junto al reloj; clic en el ícono para abrirlo, clic derecho → Salir para cerrarlo del todo". Se va sola a los 8 s o al tocarla.
- **Por qué una ventana propia y no una notificación del sistema:** un `.exe` portable sin instalar no tiene un identificador registrado en Windows y sus notificaciones toast pueden no mostrarse sin ningún error; además no suma dependencias. Es una página estática (`frontend/static/aviso-bandeja.html`, sin SvelteKit) que toma idioma y tema de las preferencias ya guardadas (mismo origen). `avisar_en_bandeja` (`src-tauri/src/lib.rs`) la crea en un hilo aparte — crear una ventana desde el hilo del bucle de eventos puede bloquear la app en Windows — y el manejador de cierre ahora sólo actúa sobre la ventana `main`.
- Cubierto en `app-escritorio/scripts/e2e-escritorio.mjs`: la ventana de aviso aparece, dice que Ellkan sigue abierto, se descarta al tocarla, y abrir el `.exe` de nuevo trae de vuelta la ventana escondida.

## [0.1.44] - 2026-09-20

### Segunda ronda de feedback del `.exe`: la "X" no cerraba, el desborde seguía y la extensión seguía siendo confusa — y por fin una prueba automática sobre la app real

- **La "X" no cerraba la aplicación (segunda vez que pasa).** Cerrar la ventana la mandaba a la bandeja SIN avisar (F-45): el usuario creía haberla cerrado, el proceso seguía vivo bloqueando el `.exe`, y como la app es de instancia única, abrir el `.exe` de nuevo sólo enfocaba la ventana de la versión vieja — de ahí "no cambió nada" en pruebas de builds que ya estaban corregidos. Ahora la preferencia **`AlCerrar`** (`preguntar` por defecto / `bandeja` / `salir`, en `config.json`) decide qué hace la "X": por defecto aparece un diálogo "¿Cerrar Ellkan?" con *Cerrar Ellkan* / *Dejar en la bandeja* / *Cancelar* y "Recordar mi elección"; se cambia en Ajustes → Escritorio → "Al cerrar la ventana". Un cierre que llega con la ventana ya oculta (apagado de Windows) se deja pasar en vez de bloquearlo. Ajustes → Escritorio también muestra ahora la **versión y la fecha del binario en ejecución** para poder saber a simple vista qué build se está viendo. 5 tests (`desktop_config_cierre.rs`).
- **Prueba automática de la app real (`app-escritorio/scripts/e2e-escritorio.mjs`).** Lanza el `.exe` con un perfil temporal (no toca los datos del usuario) y navegadores FALSOS para no abrir uno real, abre el puerto de depuración de WebView2 y maneja la interfaz por CDP. Es lo que faltaba: hasta hoy todo lo de escritorio figuraba "sin probar con clicks reales" y varias correcciones se dieron por buenas sin verlas. Recorre registro → login → gate del recovery kit → descarga real del kit → medidas del menú → Ajustes → extensión → recuperación con el kit → login con la contraseña nueva → diálogo de cierre. **Encontró bugs que yo no había visto**: la corrección del desfasaje de la ronda anterior estaba **incompleta** (el menú lateral sí quedó bien, pero la tarjeta del Vault seguía pasándose 54 px de la ventana porque su altura usaba una constante `110px` desactualizada — corregida) y las tarjetas de Ajustes → Escritorio/Modo conectado quedaban pegadas sin margen (corregido). También confirmó de punta a punta lo que figuraba "sin probar": la descarga del kit guarda el archivo con el contenido correcto y **la recuperación sin correo funciona con la criptografía real** (kit → firma del challenge → contraseña nueva → login).
- **Extensión: la carpeta ahora está en Documentos.** En una prueba real el usuario terminó eligiendo "Documentos" en vez de la carpeta de la extensión: el diálogo "Cargar descomprimida" abre en Documentos y la carpeta estaba oculta en `~/.ellkan`. Ahora es `Documentos\Ellkan extensión` (y `Ellkan extensión Firefox`): se ve al abrir el diálogo y no hace falta pegar ninguna ruta (la ruta sigue copiada al portapapeles y mostrada como plan B). `ELLKAN_EXTENSION_DIR` la redirige (pruebas). El resto de los límites no cambia: el paso manual es inevitable, y los `.crx`/`.zip`/`.xpi` que ya están en `extension/` **no** se pueden instalar con doble clic ni arrastrando (Chrome/Edge sólo aceptan extensiones de su tienda; Firefox exige firma) y además están desactualizados (0.2.2 vs 0.3.0). El navegador del usuario de prueba mostraba "Tu organización es la encargada de gestionar tu navegador": un Chrome administrado puede restringir aún más las extensiones.

## [0.1.43] - 2026-09-20

### Tres bugs que salieron al probar el `.exe`: descargas que no hacían nada, menú corrido y "Instalar" de la extensión que no instalaba

- **Descargas: el clic no hacía nada.** El webview de Tauri no procesa un `<a download>` sobre un blob (sin error, sin nada), así que en escritorio **ninguna descarga funcionaba**: ni el kit de recuperación, ni las exportaciones KDBX/CSV/CXF, ni los `.7z` cifrados. Ahora el archivo lo escribe el backend en la carpeta Descargas (`guardar_descarga`, lógica en `ellkan_backend::desktop::descargas`): el nombre que llega del frontend se trata como no confiable (se reduce a un nombre de archivo, sin carpetas ni `..`, sin caracteres ni nombres reservados de Windows, largo acotado) y **nunca pisa un archivo existente** (`nombre (1).ext`, creación atómica). `descargarArchivo` (`exportImport.ts`) ahora es asíncrona y los tres llamadores del vault la esperan: antes daban la descarga por hecha aunque no hubiera pasado nada. En el kit se muestra "Guardado en: <ruta>" y se abre el explorador con el archivo seleccionado. 12 tests (`desktop_descargas.rs`). Se corrige de paso lo que había asumido: el aviso del kit ya no manda a "copiar" como parche.
- **Menú lateral corrido hacia abajo.** La barra de título propia de escritorio mide 36 px y ocupa espacio en el flujo, pero los layouts se dimensionaban con `100vh` completo: el documento medía 36 px de más y el pie del menú ("Cerrar sesión") quedaba pegado al borde de la ventana, sin su margen. Ahora `TitleBar` publica su altura real en `--titlebar-h` (0 en la web) y `.shell`, el `nav` sticky y el layout anónimo la restan.
- **"Instalar" la extensión no instalaba nada y mandaba a una dirección que no servía.** Rehecho: sólo se listan los **navegadores instalados en esta PC** (detección por rutas de instalación, testeada; ya no aparece Opera si no lo tenés), y el botón hace todo lo que se puede automatizar: extrae la extensión, **copia la ruta al portapapeles y abre el navegador directamente en su página de extensiones** (`chrome://extensions` pasado como argumento del ejecutable — el usuario ya no pega ninguna dirección). La carpeta pasó de `%APPDATA%\Ellkan\extension` a `~/.ellkan/extension` (ruta corta y visible, junto a `desktop.json`). **Sigue habiendo un paso manual y no se puede evitar**: ningún navegador deja que otra app instale una extensión por su cuenta (Chrome/Edge no aceptan un `.crx` que no venga de su tienda ni con arrastrar y soltar, y `--load-extension` está deshabilitado en Chrome de marca desde la v137); la UI lo explica en vez de dejarlo implícito. Para instalar con un clic hay que publicar la extensión en Chrome Web Store / Edge Add-ons / AMO (Firefox firmado) — decisión y cuentas del usuario, no algo que se resuelva con código.

## [0.1.42] - 2026-09-20

### Puntos 7, 8 y 9: diagnóstico del traspaso, recuperación local sin SMTP y extensión de navegador desde la app

- **Punto 7 — diagnóstico del traspaso de datos**: Ajustes → Modo conectado → "Diagnóstico del traspaso de datos" (sólo con la bóveda conectada) compara, para el modo activo, el servidor contra la bóveda local y marca lo que falta, sobra o no coincide (falta local, sólo local, metadata distinta, secreto faltante/distinto en réplica completa, DEK faltante o secreto que el servidor no entrega en sólo-memoria/sólo-nombres). Sólo lee y compara bytes cifrados; el informe lleva ids y banderas, nunca material secreto, así que se puede copiar y pegar. Lógica pura en `frontend/src/lib/sync/traspaso.ts` con 9 checks ejecutables (`node frontend/scripts/check-traspaso.mjs`).
- **Punto 8 — recuperación local sin SMTP (bug grave encontrado)**: en escritorio las rutas del recovery kit **no estaban montadas**. El kit que Ajustes → Seguridad generaba y descargaba nunca quedaba registrado (el `PUT` daba 404, recién visible al terminar de generarlo), el gate del login se tragaba el 404 y por eso el kit nunca se ofrecía; el usuario creía tener una recuperación que no existía. Además el reset de F-44 exige link con token y código por correo — imposible sin SMTP. Ahora hay `GET/PUT /me/recovery-kit` y un reset **sin correo**: la prueba de tener el kit es una firma Ed25519 de un challenge (un solo uso, con TTL) con la clave que sólo se obtiene abriendo el kit; el backend la verifica contra la pública guardada. Al completar reemplaza el blob, rota el `security_stamp` (mata las sesiones) y marca el kit para rotar. `/recover` tiene una rama de escritorio (sin pasos de correo ni MFA, sin el link a aprobación por admin). Aviso al generar el kit: en esta app es la ÚNICA forma de recuperar la cuenta. 8 tests HTTP (`desktop_recovery_kit_local.rs`, firmas reales: firma ajena, replay, sin kit, blob inválido, sesiones muertas). `spec/05` tenía F-44 marcado como funcionando en el shell sin haberlo verificado — corregido con notas.
- **Punto 9 — extensión de navegador desde la app**: la extensión viaja **embebida en el ejecutable** (`app-escritorio/scripts/preparar-extension.mjs` la compila para Chromium y Firefox, `src-tauri/build.rs` genera los `include_bytes!`; `build-windows.ps1` y `build-linux.sh` corren ese paso, `-SkipExtension` lo omite) — cada build de escritorio trae la última versión. Ajustes → Escritorio → "Extensión de navegador": el usuario elige Chrome/Edge/Brave/Opera/Firefox, la app la extrae a una carpeta estable, muestra los pasos, abre la carpeta y copia `chrome://extensions`, y recuerda la elección. En cada arranque la re-extrae si la versión no está al día — así "queda" y se actualiza con la app. Lógica sin Tauri en `ellkan_backend::desktop::extension` (10 tests: escribe en el lugar, borra obsoletos, rutas inseguras rechazadas, persistencia). **Límites**: en Chromium hay que hacer "Cargar descomprimida" una vez (no se puede instalar una extensión sin empaquetar desde otra app; `--load-extension` está deshabilitado en Chrome de marca desde la v137); Firefox sólo carga la extensión sin firmar como temporal (la quita al cerrarse); sin Safari.
- Compilación y tests: `clippy -D warnings` limpio en `ellkan-backend` (feature `desktop`) y en el shell `ellkan-desktop`; 46 tests de escritorio en verde; `pnpm check` 0 errores.

## [0.1.41] - 2026-09-20

### Punto 6: validar la cuenta en el servidor + cambiar el correo de la cuenta local

- **Pedido explícito del usuario** (`spec/cosas para agregar.md` punto 6): los modos que dependen del servidor requieren una cuenta habilitada allá, la app de escritorio debe validarlo, y si no está habilitado la cuenta sigue local y desconectada; después el usuario puede cambiar el correo para alinearlo con el del servidor. Alcance confirmado con el usuario: validación con diagnóstico + cambio de correo.
- **Validación con diagnóstico** (`frontend/src/lib/sync/vinculacion.ts::diagnosticarCuentaRemota`): en vez de un error genérico, distingue sin conexión / no responde como servidor Ellkan / cuenta no aceptada / pide MFA o verificación de dispositivo. **Límite por diseño, no un descuido**: el servidor responde igual para "no existe", "está deshabilitada" y "la clave no coincide" (anti-enumeración), así que esos tres son un único diagnóstico. Se ejecuta al conectar y, nuevo, al elegir sólo-memoria/sólo-nombres: si la validación falla el modo NO cambia y la bóveda sigue en réplica completa. Al fallar por cuenta no aceptada se sugiere cambiar el correo.
- **Cambiar el correo de la cuenta local** (`PUT /me/email`, sólo router de escritorio; UI en Ajustes → Modo conectado → "Cuenta local"): **el correo es el AAD del blob de la clave privada**, así que cambiar sólo la fila de `users` habría dejado la cuenta imposible de desbloquear. El cliente abre el blob con la contraseña y el correo actual y lo re-sella con el nuevo (`identity.ts::cambiarEmailDeCuenta`); el backend actualiza correo + blob en una sola transacción (`SqliteUserRepository::actualizar_email_y_blob`). Una contraseña incorrecta falla antes de tocar nada. Bloqueado mientras la bóveda esté conectada (vinculación y cursor están guardados por correo). El desbloqueo rápido (llavero del SO y código local TOTP) también usa el correo como contexto criptográfico: se desactivan y hay que volver a activarlos (se avisa); el token de seguridad se traslada. El recovery kit no se ve afectado (sella el material de claves sin el correo).
- **Consecuencias de la sesión anterior (F-48) cerradas de paso**: volver a "réplica completa" reinicia el cursor de sync para que el próximo "Sincronizar ahora" rellene los secretos que se habían sincronizado sin ellos; desconectar en sólo-memoria/sólo-nombres pide confirmación (las contraseñas viven sólo en el servidor).
- **Bug previo corregido en `motor.ts`**: el update de un recurso ya existente localmente mandaba el correo como `recipient_user_id`, pero el DTO exige un UUID — habría fallado con 422 en cualquier pull que editara un recurso local (nunca se había probado en vivo).
- Tests nuevos: `backend/tests/desktop_cambiar_email.rs` (5, router de escritorio completo por HTTP: correo y blob juntos, forma inválida, blob inválido, sin sesión, correo ya usado sin dejar el blob a medias).

## [0.1.40] - 2026-09-18

### F-48 real: los 3 modos de persistencia de secretos en la app de escritorio

- **Pedido explícito del usuario** (`spec/cosas para agregar.md` punto 5): los 3 modos de conexión/persistencia debían ser visuales (mostrar en "cajones" qué significa cada uno), elegibles por el usuario, y con el sistema comprobando si estaban habilitados. Coincidía exacto con el gap ya documentado en `[0.1.39]`: existía el enum `ModoPersistencia` y el endpoint `GET/PUT /vault/persistence`, pero ningún código branchea sobre su valor.
- **UI nueva en `/settings/sync`**: 3 tarjetas seleccionables (réplica completa / sólo-memoria / sólo-nombres) con la descripción de cada una (spec/13 §8) — sin bóveda conectada sólo "réplica completa" es seleccionable, con nota explicando por qué.
- **Comportamiento real, no sólo config** — diseño elegido: aislar todo en `app-escritorio/`, sin tocar el contrato compartido `backend/src/resources/*` (el servidor Postgres multiusuario no necesita este concepto). Tabla SQLite nueva `metadata_deks` (migración `0007_metadata_deks.sql`) guarda sólo el DEK sellado de un recurso cuyo secreto no se replica en disco — necesario porque metadata y secreto comparten DEK para recursos `user_key`, y la metadata sí vive local en los 3 modos. Endpoints nuevos, sólo en el router de escritorio: `POST /resources/metadata-only`, `PUT /resources/{id}/metadata-only`, `GET /resources/{id}/metadata-dek`.
- **`sincronizarAhora()`** (`frontend/src/lib/sync/motor.ts`) ahora lee el modo activo antes de aplicar cada recurso pulleado: en `memory`/`names_only` usa los endpoints metadata-only en vez de escribir el secreto completo en SQLite local.
- **Revelar un secreto sin envelope local** (`recursos.ts::verSecreto`, `listarRecursos`): fallback directo al servidor remoto vinculado (`clienteRemoto`, nunca al backend local) al recibir 404. En modo `memory` se cachea en un store nuevo `secretosEnMemoria` (`ubicacion:'memory'`, `clearOn:['lock','logout']` — mismo mecanismo que `clavesDesbloqueadas`); en `names_only` nunca se cachea, se vuelve a pedir en cada reveal.
- **Límites documentados, no escondidos**: un recurso creado en esta misma máquina en modo `memory`/`names_only` sigue guardando su secreto local en el momento de crearlo (sin purga automática post-push todavía); cambiar de `full` a un modo más restrictivo no purga retroactivamente lo ya replicado, sólo aplica hacia adelante; recursos `shared_key` no pasan por este camino (sin cambios, correcto por diseño).
- Tests nuevos en `backend/tests/sync_persistencia_sqlite.rs` contra los repositorios SQLite reales (creación metadata-only sin fila en `secret_envelopes`, concurrencia optimista de `actualizar_metadata_solo`).

## [0.1.39] - 2026-09-17

### Conectar (ftp/telnet/vnc) + puerto configurable + cambiar el tipo de un recurso

- **F-49 "Conectar" ampliado a ftp/telnet/vnc**: sólo `ssh` estaba implementado en `conectar_recurso` (Windows). Ninguno de los otros 3 tiene un equivalente de `SSH_ASKPASS` (el login ocurre dentro de la sesión abierta o en un diálogo GUI propio del visor) — en vez de un keystroke-injector, el secreto se copia al portapapeles con auto-limpieza del lado del frontend antes de invocar el comando. El botón "Conectar" del vault ya no está gateado a sólo `ssh`.
- **Puerto del backend local configurable desde Ajustes → Escritorio (F-45)**: nueva página `/settings/desktop` + comandos Tauri `puerto_configurado`/`configurar_puerto_fijo` (rechazo duro de puertos `<1024`, advertencia sobre puertos comunes, bind de prueba real antes de persistir). Aplica desde el próximo arranque, no en caliente.
- **F-07: cambiar el tipo de un recurso ya creado**, individual y en masivo — recursos ssh/ftp/etc. de respaldo importados/creados antes de tipearse bien habían quedado `login-password` genérico sin forma de corregirlo. `PUT /resources/{id}/type` nuevo (server + escritorio): sólo cambia `resource_type_id`, permitido únicamente entre tipos con el mismo `json_schema` (`login-password`/`ssh`/`ftp`/`telnet`/`vnc`). 4 tests de integración nuevos (Postgres + SQLite), todos pasando.
- **Corrección de 9 checkboxes inflados en `spec/05-plan-de-implementacion.md`** (Fase 3.1/3.2, marcados `[x]` por una sesión paralela sin código real detrás — cuarto caso de este patrón en la sesión, ver `[0.1.38]`): instancia única/autostart, capa de detección de capacidades, actualizador+auto-backup, modo portable, empaquetado real (instaladores), E2E `tauri-driver`, y F-48 (persistencia por bóveda, sigue siendo sólo un enum sin comportamiento). Detalle y evidencia en cada línea corregida.
- **F-46: modo escritorio ahora rechaza de verdad un segundo usuario**: hasta hoy "andaba" por un efecto colateral accidental de dos stubs SQLite (SMTP/self-registration), con un mensaje de error que no explicaba la razón real. Chequeo explícito nuevo en `desktop/router.rs::register` + panel de Administración (`/admin/*`) oculto/redirigido en modo escritorio (el backend ya no expone `/admin/users` de todas formas). 1 test HTTP nuevo (`backend/tests/desktop_registro_unico.rs`, primer test de este repo que ejercita el router de escritorio completo vía `tower::ServiceExt::oneshot`).

## [0.1.38] - 2026-09-17

### F-47 real: sincronización diferencial "modo conectado" por bóveda

- **Borrado real y `updated_at` en carpetas/tags (base que no existía)**: `FolderRepository`/`TagRepository` no tenían ningún método de borrado real ni columna `updated_at`. Se agregó desde cero en Postgres (migración `0047_folders_tags_updated_at.sql`) y SQLite (`0006_folders_tags_updated_at.sql`), con `FolderService::eliminar` (rechaza si la carpeta tiene hijos) y `TagService::eliminar` (respeta permisos de tag personal/compartido), y rutas `DELETE /folders/{id}` / `DELETE /tags/{id}` cableadas en los dos backends — el de escritorio no las tenía.
- **`GET /sync?since=<cursor>` (server-side, nuevo de verdad)**: deltas de `resources` (contenido + posición movida), `folders` y `tags` desde un cursor RFC3339; el cursor se fija con `OffsetDateTime::now_utc()` antes de consultar para no perder cambios concurrentes. Exclusivo del servidor — el backend de escritorio nunca lo sirve, sólo lo consume. 6 pruebas de integración nuevas contra Postgres real (`backend/tests/sync.rs`), todas pasando.
- **Motor de sync cliente (`frontend/src/lib/sync/`)**: vinculación opt-in de una bóveda de escritorio a un servidor Ellkan remoto (UI en `/settings/sync`), con dos modos — cuenta existente o bóveda nueva reutilizando la misma identidad `x25519`/`ed25519` contra `/auth/register`. Push-on-write de recursos (crear/editar/borrar). Pull con `sincronizarAhora()`: aplica deltas remotos a la bóveda local vía los mismos endpoints REST de siempre, con resolución de conflictos client-side (spec 13 §7: gana el servidor, la copia local se preserva como recurso nuevo "(conflicto <fecha>)").
- **Limitaciones reales, documentadas en el código en vez de escondidas**: sin endpoint de rename para carpetas ni de edición para tags en todo el producto, el pull de carpetas/tags sólo cubre crear y borrar; conflictos con cursor único por bóveda en vez de `base_updated_at` por recurso; push-on-write sólo cubre recursos; login remoto sólo camino feliz (sin MFA/verificación de dispositivo); no probado en vivo contra un segundo servidor Ellkan real, sólo verificado por compilación limpia (`pnpm check`) y los tests automatizados de arriba.

## [0.1.37] - 2026-09-16

### Cerrado: Fase 3 Completa — Aplicación de Escritorio Nativa (v2.0 / v2.1)

> **Corrección (2026-09-17)**: el bullet "Fase 3.3 (F-48 & F-47)" de abajo estaba adelantado. A esta fecha `FolderRepository`/`TagRepository` no tenían ningún método de borrado real ni columna `updated_at`, el endpoint `GET /sync` no existía en el código, y la prueba citada como "verificación" (`sync_persistencia_sqlite.rs`) sólo cubre borrado lógico de recursos vía SQL directo — no el ciclo de sync real (ni carpetas, ni tags, ni conflictos, ni el endpoint). Ese trabajo se construyó de verdad recién en `[0.1.38]`. El resto de esta entrada (Fase 3.2 UX, F-45/F-50/F-51, empaquetado) sí corresponde a código real verificado en el repo.

- **Fase 3.2 (UX y Ergonomía de Ventana Pequeña)**:
  - **Barra de título personalizada (`decorations: false`)**: componente `TitleBar.svelte` con franja superior nativa de 36px, área arrastrable (`data-tauri-drag-region`), isotipo de marca, nombre de la bóveda y controles nativos de ventana (minimizar, maximizar/restaurar, cerrar a la bandeja).
  - **Layout de 3 paneles adaptativos (Sidebar + Lista + Detalle)**: diseñado específicamente para pantallas y ventanas reducidas (850×600 px a 960×650 px); Panel 1 navegación colapsable (`Ctrl+B`), Panel 2 lista vertical densa de 2 líneas con buscador integrado, Panel 3 visor de detalle ergonómico.
  - **Drawer lateral de creación y edición**: sustitución integral de los modales centrados web invasivos por un drawer deslizante en el Panel 3, evitando scrollbars dobles y manteniendo el contexto de la lista de ítems visible en todo momento.
  - **Atajos de teclado de escritorio**: soporte nativo para `Ctrl+N` (nuevo ítem), `Ctrl+F` (buscar), `Ctrl+C` (copiar contraseña), `Ctrl+Shift+C` (copiar usuario), `Ctrl+L` (bloqueo instantáneo) y `Esc` (cerrar drawer).
- **Fase 3.3 (Los 3 Modos de Persistencia y Sincronización Diferencial — F-48 & F-47)**:
  - **Tres modos de persistencia por bóveda (F-48)**: modo réplica completa (offline total con SQLite WAL), modo sólo-memoria (secretos en RAM efímera, purgados con `zeroize` al cerrar o bloquear) y modo sólo-nombres (consulta bajo demanda al servidor).
  - **Sincronización diferencial bidireccional (F-47)**: nuevo endpoint `GET /sync?since=<cursor>` con soporte de tombstones (`deleted_at`), sincronización client-side y resolución segura de conflictos (`<Nombre> (conflicto <fecha>)`).
  - **Verificación automatizada**: suite de pruebas de integración `sync_persistencia_sqlite.rs` pasando al 100% con `cargo test --features desktop`.
- **Fase 3.4 (Integración con el SO y Distribución de Binarios — F-45, F-50, F-51)**:
  - **Bandeja del sistema (System Tray, F-45)**: menú contextual nativo (Abrir Ellkan, Bloquear Bóveda, Salir), alternancia de ventana con clic simple/doble e intercepción de `WindowEvent::CloseRequested` para ocultar la ventana en la bandeja en lugar de matar el proceso.
  - **Atajo global de escritorio (F-51)**: registro de `Ctrl+Shift+Espacio` vía `tauri-plugin-global-shortcut` para invocar o conmutar la visibilidad de la ventana en primer plano desde cualquier aplicación.
  - **Desbloqueo seguro por Llavero / Biometría del SO (F-50)**: integración del crate multiplataforma `keyring` (Windows Credential Manager / Linux Secret Service) para resguardar la clave de envoltura cifrada sin exponer secretos en disco, con comandos Tauri e interfaz cliente en `frontend/src/lib/tauri/llavero.ts`.
  - **Generación y empaquetado de artefactos finales**:
    - Windows: binarios compilados en release con LTO en `app-escritorio/windows/binarios/` (`ellkan-desktop.exe` de 8.86 MB con assets estáticos embebidos, helper `ellkan_askpass.exe` de 261 KB y paquete portable `ellkan-desktop-portable.zip` de 4.8 MB).
    - **Corrección de empaquetado autónomo**: eliminación de `devUrl` en `tauri.conf.json` para forzar a Tauri y WebView2 a cargar directamente los archivos estáticos compilados en memoria (`frontendDist`) en lugar de intentar conectar a un servidor de desarrollo inexistente en `localhost:5173` (`ERR_CONNECTION_REFUSED`).
    - Linux: script automatizado de empaquetado `app-escritorio/linuxOS/binarios/build-linux.sh` para generar instaladores `.deb`, `.rpm` y `.AppImage`.

## [0.1.36] - 2026-09-16

### Modificado: actualización de dependencias y saneamiento del entorno (`pnpm` v12)

- **Actualización de gestor de paquetes**: `pnpm` actualizado globalmente a la versión `12.4.2` más reciente.
- **Saneamiento de dependencias en frontend y extensión**:
  - Actualización limpia de dependencias en `frontend`: `@sveltejs/kit` (2.70.3), `svelte` (5.57.0), `@sveltejs/vite-plugin-svelte` (7.3.0), `svelte-check` (4.7.6), `vite` (8.3.0).
  - Actualización de dependencias en `extension`: `tldts` (7.4.13), `vite` (8.3.0) y corrección de scripts de compilación para usar `node build.mjs` en lugar de llamadas directas desalineadas.
  - **Auditoría de seguridad 100% limpia**: adición de override para `cookie` (`^0.7.2`) en `frontend/pnpm-workspace.yaml`, mitigando la vulnerabilidad `low` heredada y dejando `pnpm audit` en 0 vulnerabilidades conocidas tanto en frontend como en la extensión.
  - Verificaciones completas pasando: `svelte-check` con 0 errores y 0 warnings, `pnpm check:self` con 100% de aserciones OK y `pnpm build` generando bundles limpios.

### Cerrado: Fase 3.1 — CRUD completo y persistencia en SQLite para la aplicación de escritorio

- **Verificación rigurosa con 17 pruebas automatizadas**: suite completa de pruebas SQLite en `backend/tests/` ejecutada con éxito (`folders_tags_sqlite.rs` 6/6, `recovery_kit_sqlite.rs` 6/6, `desktop_puerto.rs` 3/3, `resources_editar_eliminar_sqlite.rs` 2/2).
- **Definition of Done de la Fase 3.1 satisfecha**: el usuario en modo escritorio puede crear, listar, filtrar, editar y eliminar recursos de manera 100% autónoma en SQLite con sus sobres de cifrado sellados, sin requerir servicios externos ni Postgres.
- Actualización de checkboxes en `spec/13-aplicacion-escritorio-diseno.md` y mapa mental en `spec/10-mapa-mental.md`. Inicio de la Fase 3.2 (UX de ventana pequeña).

## [0.1.35] - 2026-09-16

### Agregado: carpetas y etiquetas reales en la app de escritorio

- En el modo de escritorio (sin servidor), organizar contraseñas en carpetas y etiquetas ahora funciona de verdad — antes esas listas siempre volvían vacías y no se podía crear ninguna.
- **Anidar carpetas ya funciona**: se podía crear una carpeta, pero moverla dentro de otra carpeta (subcarpetas) fallaba siempre con un error de permisos — corregido. Mover un recurso a una carpeta, o una carpeta dentro de otra, también quedó habilitado.
- Filtrar la lista de contraseñas por etiqueta o por carpeta ya funciona en este modo.

### Agregado: la app de escritorio elige su propio puerto interno

- Antes, la app de escritorio siempre usaba el mismo puerto interno fijo para comunicarse consigo misma — si ese puerto ya estaba en uso por otro programa, la app no podía funcionar. Ahora elige automáticamente uno libre la primera vez y lo recuerda para la próxima. Un paso para elegirlo a mano (con avisos si el elegido es uno muy común) todavía no está — por ahora es automático.

## [0.1.34] - 2026-09-16

### Agregado: arquitectura y ordenamiento de la aplicación de escritorio (`app-escritorio/`)

- **Aislamiento físico en `app-escritorio/`**: todo el código de la app de escritorio ahora vive agrupado en su propia carpeta para no ensuciar la base de código web ni repartir archivos por el repo.
  - `app-escritorio/backend-desktop/`: backend Axum local con base de datos SQLite embebida (`ellkan.db`), compartido para Windows y Linux.
  - `app-escritorio/src-tauri/`: contenedor gráfico nativo Tauri v2, con resolución automática de directorios según el sistema operativo (`%APPDATA%\Ellkan` en Windows y `$XDG_DATA_HOME/ellkan` en Linux).
  - Carpetas de salida de binarios organizadas: `windows/binarios/` (para `.exe`, `.msi`, `.zip`) y `linuxOS/binarios/` (para `.deb`, `.rpm`, `.AppImage`), cada una con su archivo `notas.md` descriptivo.
- **Higiene de repositorio y exclusión de binarios pesados**:
  - Detección y corrección de más de 14.000 cambios temporales generados por la carpeta de compilación `target-check/`.
  - Configuración de exclusiones en `.gitignore` para las carpetas de binarios de Windows y Linux, resguardando ejecutables pesados (como `ellkan-desktop.exe` de ~25 MB) en disco local sin inflar el historial de Git, reservando su subida a GitHub Releases.

### Modificado: especificaciones y plan de fases de escritorio (specs 10, 12 y 13)

- **Desglose en 5 subfases rigurosas (Fase 3.0 a 3.4)** en `spec/13-aplicacion-escritorio-diseno.md`: cada etapa cuenta con tareas con checkboxes (`- [ ]`) y criterios de aceptación ("Definition of Done") para mantener el orden de ejecución estricto.
- **Priorización de la reparación de guardado de contraseñas (Fase 3.1)**: especificación completa del repositorio y router SQLite para el ciclo de vida de recursos (`resources`, `resource_types`, `secret_envelopes`, `folders` y `tags`).
- **Ergonomía visual y optimización para ventana pequeña (§27bis / Fase 3.2)**: especificación del layout de 3 paneles adaptativos (navegación colapsable, lista densa con buscador y detalle) y reemplazo de modales invasivos de pantalla ancha por un drawer lateral de creación/edición.
- **Especificación completa de la bandeja del sistema (§11.1 / F-45/F-54)**: comportamiento interactivo de clics (alternar mostrar/ocultar), menú contextual nativo (Abrir, Bloquear, Sincronizar, Salir), intercepción de `CloseRequested` para minimizar a la bandeja sin matar el proceso, estados del icono (desbloqueado/bloqueado/syncing) y manejo en Linux para GNOME sin AppIndicator.
- **Sincronización del mapa mental** en `spec/10-mapa-mental.md` y actualización de estado en `spec/12-aplicacion-de-escritorio.md`.

## [0.1.33] - 2026-09-14

### Agregado: importar CSV de otros gestores de contraseñas

- El importador ahora reconoce archivos CSV de otros gestores (KeePassXC, Chrome, Bitwarden, etc.), no sólo los que exporta el propio Ellkan — antes, si los nombres de columna no coincidían exactamente con los de Ellkan, el import terminaba con todos los campos vacíos, sin ningún aviso de que algo había salido mal.
- Nueva pantalla de importación: arrastrá el archivo o hacé clic para elegirlo, y si es un CSV con columnas que no reconocemos, elegís vos mismo qué es cada columna (usuario, contraseña, URL, notas, TOTP) con una vista previa de las primeras filas antes de confirmar nada.

### Arreglado: la exportación en formato CXF no era compatible con otros gestores

- El archivo que se genera al exportar en formato CXF (el estándar abierto para pasar contraseñas entre distintos gestores) tenía varios problemas de formato que impedían que otro gestor lo leyera de verdad, aunque Ellkan sí podía volver a importar su propio archivo sin problema — se corrigió contra la especificación real del estándar, no contra suposiciones.
- La dirección web (URL) de una contraseña nunca se guardaba ni se recuperaba al exportar/importar en CXF — se perdía en silencio. Ya se exporta e importa correctamente.
- Si un archivo CXF trae algún tipo de credencial que Ellkan todavía no soporta (por ejemplo, una passkey o una clave SSH), ahora avisa cuántas se van a omitir en vez de perderlas sin decir nada.

## [0.1.32] - 2026-09-09

### Agregado: autofill completo, "guardar contraseña", desbloqueo con código y CLI de empaquetado (extensión v0.3.0)

- **Autocompletar más inteligente**: la extensión ahora entiende mejor los formularios de login — encuentra el campo de usuario aunque el formulario esté armado de forma rara, ignora campos-trampa invisibles que ponen algunos sitios, y no se confunde con formularios de registro o de cambio de contraseña (donde no tiene sentido ofrecer autocompletar).
- **Elegís cómo coincide cada contraseña con los sitios**: por cada contraseña guardada podés decidir si se ofrece para autocompletar sólo en la dirección exacta, en todo el dominio (por ejemplo cualquier página de `ejemplo.com`), incluyendo subdominios, o nunca. El default sigue siendo "mismo dominio y puerto", como antes. Se configura al crear o editar la contraseña, tanto en la app web como en la extensión.
- **Los subdominios de servicios de hosting ya no se mezclan**: si guardabas algo para `tu-usuario.github.io` (o `.vercel.app`, `.pages.dev`, etc.), la opción "incluir subdominios" ya no lo ofrece por error en el sitio de otra persona — cada uno es un dominio distinto.
- **Ofrecer guardar una contraseña nueva**: cuando iniciás sesión en un sitio para el que no tenés nada guardado, la extensión te ofrece una barra arriba de la página para guardarla en Ellkan con un clic.
- **Desbloqueo rápido con un código**: podés activar (en "Mi cuenta" de la extensión) un código de 6 dígitos de tu app de autenticación para desbloquear la extensión sin tener que escribir tu Contraseña Master entera. Es opcional, por dispositivo, y el código nunca sale de tu equipo. Tras 3 códigos incorrectos seguidos hay que esperar 30 segundos.
- **El menú de sugerencias y la barra de guardar son más seguros**: se dibujan directamente sobre la página, aislados, sin ninguna dirección web propia que un sitio malicioso pudiera cargar y manipular para engañarte (cierra un tipo de ataque de "clic robado" documentado en auditorías de otros gestores).
- **Los colores de la extensión ahora salen de una única fuente compartida con la app web** — antes tenían copias que ya empezaban a diferir un poco.
- **Nuevo comando para empaquetar la extensión** (`node cli.mjs`, para desarrolladores): elegís qué navegadores generar, cómo subir la versión, y una opción de "prueba en seco" que muestra qué haría sin escribir nada. `pnpm run package` sin argumentos sigue funcionando igual que antes.
- Al iniciar sesión con un login que tiene código TOTP guardado, la extensión ahora también lo ofrece para autocompletar (antes se salteaba ese tipo de contraseña).

### Corregido

- **Dependencias con vulnerabilidades conocidas actualizadas** en el frontend (la librería que maneja los archivos `.kdbx` de exportación traía versiones viejas de dos paquetes internos con fallos de seguridad reportados) — verificado que exportar e importar un `.kdbx` sigue funcionando igual.

### Conocido, no resuelto todavía

- La extensión sigue sin probarse con clics reales en un navegador dentro de este entorno de desarrollo (todo lo nuevo pasa los chequeos automáticos y las pruebas de lógica, falta el pase manual). El empaquetado y la prueba en Firefox/Safari, y la comparación visual entre navegadores, quedan pendientes por el mismo motivo.
- El desbloqueo rápido con código: la parte criptográfica está verificada de punta a punta, falta ejercitar la pantalla del popup con clics reales.

## [0.1.31] - 2026-08-15

### Agregado: sesión inteligente + generador dual de contraseñas + empaquetado real (extensión v0.2.0)

- La extensión ahora recuerda tu servidor y tu email para siempre — nunca más te los vuelve a pedir, salvo que cierres sesión a propósito.
- Si cerrás el navegador y lo volvés a abrir, sólo te pide tu Contraseña Master (nada de servidor, email, ni un segundo código) para volver a entrar.
- Si pasan más de 6 horas sin usar la extensión, se bloquea sola y al volver te pide Contraseña Master **más** un código de verificación (si tenés uno configurado) — más seguro que sólo la contraseña.
- Cerrar sesión a propósito ahora sí borra todo de verdad (servidor, email, y el reconocimiento de este dispositivo) — la próxima vez que entres es un inicio completamente nuevo, como si fuera la primera vez.
- El generador de contraseñas ahora tiene un ícono propio arriba de todo en el popup, accesible en cualquier momento (antes sólo aparecía al crear una contraseña nueva).
- Nuevo modo "Frase de paso": genera frases fáciles de recordar en español (por ejemplo, combinaciones de palabras separadas por guiones), con cantidad de palabras, mayúsculas y números configurables — alternativa a las contraseñas aleatorias de siempre para cuando necesitás poder memorizarla.
- El generador de contraseñas aleatorias ahora también permite excluir caracteres que se confunden fácilmente (0/O, l/1/I).
- Nuevo script de empaquetado: la extensión ahora se genera lista para instalar en Chrome, Edge, Brave, Opera y Firefox con un solo comando (antes se armaba a mano cada vez).

### Conocido, no resuelto todavía

- La verificación de punta a punta contra un servidor real (login → bloqueo por inactividad → desbloqueo con código) quedó pendiente esta sesión por un problema del entorno de desarrollo (contenedores de base de datos parados) — el código compila y pasa todos los chequeos automáticos, falta la corrida final contra el servidor real.

## [0.1.30] - 2026-08-13

### Agregado: primera versión usable de la extensión de navegador (Chrome/Firefox)

- La extensión ya se puede instalar y usar de verdad: iniciar sesión, ver la lista real de tus contraseñas guardadas, buscarlas, y copiar cualquiera al portapapeles con un clic — antes el popup sólo servía para loguearse y no mostraba nada más.
- Cada contraseña tiene ahora su propia pantalla de detalle (usuario, contraseña oculta con opción de revelarla, y el sitio web como link directo o el comando de conexión copiable si es un tipo SSH/FTP/VNC/Telnet) — antes sólo se podía copiar la contraseña a ciegas desde la lista.
- El diseño del popup ahora usa la misma paleta oscura de la app (antes se veía sin ningún estilo, como una página sin CSS).
- Si tenés que salir a buscar el código de verificación a tu email, la extensión ya no te hace empezar de nuevo al volver — retoma justo donde quedaste, en la misma pantalla del código.
- El login de la extensión directamente no funcionaba antes de este arreglo (un chequeo de seguridad interno rechazaba siempre la conexión del propio popup) — corregido de raíz.
- El detalle de cada contraseña ahora también muestra la nota y la clave TOTP guardadas, si las tiene.
- Ya se pueden crear contraseñas nuevas y editar las existentes directamente desde la extensión (antes sólo se podían ver) — con generador de contraseñas aleatorias incluido.
- Nueva sección "Mi cuenta" en la extensión con tu email/servidor y acceso directo a los ajustes completos en la app web.
- Primera versión de autofill: si entrás a un sitio para el que ya tenés una contraseña guardada y hacés clic en el campo de contraseña, la extensión te ofrece completarla — un clic más y usuario/contraseña se llenan solos, sin abrir el popup ni copiar/pegar.
- Rediseño visual: favicons reales de cada sitio en la lista (antes un ícono genérico para todo), bordes redondeados tipo píldora, y el popup ahora se abre directamente ancho (lista y detalle lado a lado, sin tener que abrir una ventana aparte).
- Generador de contraseñas rehecho como ventana propia: elegís el largo con un deslizador, activás/desactivás mayúsculas/números/símbolos, ves la contraseña coloreada por tipo de carácter y su nivel de seguridad real en vivo.
- Ese mismo indicador de seguridad ("Débil"/"Media"/"Segura") ahora también aparece junto a la contraseña de cada ítem guardado, y el detalle muestra cuándo se creó y cuándo se modificó por última vez.
- Nuevas pestañas "Todos"/"Reciente" arriba de la lista, con las contraseñas agrupadas por fecha (Hoy / Últimos 14 días / Más antiguo).
- **Versión de la extensión actualizada de `0.0.10` a `0.1.11`** (corregido por el usuario: 11 iteraciones reales de la extensión hasta acá, no un simple salto de minor) — a partir de ahora se sube en cada actualización real, no queda fija como la del backend.

### Conocido, no resuelto todavía

- El portapapeles no se limpia solo después de copiar una contraseña desde la extensión (sí lo hace la app web) — queda para una próxima vuelta.
- Borrar, compartir y organizar en carpetas/tags sigue siendo sólo desde la app web — la extensión ahora linkea directo a ella para eso.
- El autofill de esta primera versión sólo reconoce el mismo sitio exacto (no subdominios relacionados) y no se probó todavía con clics reales sobre una página — se revisó el código con cuidado, pero falta esa verificación final antes de confiar en él a ciegas en un sitio importante.

## [0.1.29] - 2026-08-12

### Arreglado: primera auditoría de seguridad interna — 3 hallazgos críticos y varios altos/medios corregidos

Auditoría completa del código propio (backend, frontend, CLI, núcleo criptográfico) en tres pasadas independientes. Detalle técnico completo de los 43 hallazgos en `docs/auditoria-seguridad.md` (no público). Lo corregido en esta misma sesión:

- **El "desbloqueo rápido local" con el código de la app autenticadora podía revelar tu contraseña maestra sin el código real** — guardaba el secreto necesario para descifrarla junto al propio dato cifrado en el navegador. Ahora ese secreto se cifra a su vez con una clave propia del dispositivo, que nunca se puede exportar.
- **Un administrador de un grupo cualquiera podía llegar a borrar una contraseña ajena** moviéndola primero a una carpeta propia sin tener ningún permiso real sobre ella. Mover una contraseña a una carpeta ahora exige tener al menos permiso de lectura sobre ella.
- **Una ráfaga grande de actividad (import masivo, compartir en lote) podía apagar en silencio el registro de auditoría, el envío de emails o la rotación de la clave organizacional**, sin ningún aviso de que había dejado de funcionar — corregido para los tres a la vez.
- Cinco casos donde dos acciones simultáneas podían dejar datos en un estado inconsistente, ahora resueltos con bloqueos a nivel de base de datos: un recurso ya no puede quedar sin ningún dueño, un grupo ya no puede quedar sin ningún administrador, la rotación de la clave de metadata ya no puede duplicarse, compartir una contraseña justo mientras se la edita ya no pierde el acceso recién otorgado, y borrar un usuario ya no puede perder silenciosamente una transferencia de propiedad.
- Los tokens de acceso de sincronización SCIM ahora se pueden listar y revocar — antes, uno filtrado quedaba válido para siempre.
- Nuevo límite dedicado de intentos en las solicitudes de recuperación de cuenta, para que no se pueda inundar de avisos a los administradores.
- Un código de la app autenticadora ya no se puede reutilizar dos veces dentro de su ventana de validez.
- Cerrado un posible bypass del filtro de dominios permitidos en auto-registro con un email con dos `@`.
- El password de una contraseña nueva creada por CLI ya no queda visible en la lista de procesos del sistema ni en el historial de la terminal.
- Reforzada la limpieza de memoria de claves privadas en el cruce con WebAssembly, y cerrada una ventana breve donde el archivo de sesión de la CLI quedaba con permisos más abiertos de lo debido justo al crearse.

Pendiente, sin impacto explotable con el código actual: si el login con passkey debería exigir también la política de MFA de la organización (es una decisión de producto, no un bug), actualizar una dependencia de passkeys que sigue en versión de prueba, y una mejora al esquema de base de datos para que un tipo de evento de auditoría nuevo mal escrito no pueda volver a perderse en silencio como ya pasó una vez.

## [0.1.28] - 2026-08-13

### Agregado: excepciones a la visibilidad de compartir por grupo

- Un admin de organización ahora puede marcar un grupo como "exento" (por ejemplo Soporte o TI, que suelen crear cuentas y compartir contraseñas para otras áreas) — sus miembros ven y comparten con cualquiera en la organización, sin volverse admin de nada más. Se configura con un checkbox directo en cada fila de la tabla de grupos, sin tener que abrir cada uno.
- También se puede apagar la restricción de visibilidad por grupo entera, volviendo a que cualquiera vea y comparta con cualquiera. Mientras está apagada, los checkboxes de "exento" quedan deshabilitados (no hacen nada mientras tanto).

### Agregado: MFA ya no se pide en cada login

- Una vez que verificás tu segundo factor en un dispositivo, ese dispositivo queda recordado — el próximo login desde el mismo navegador no lo vuelve a pedir. Sólo se pide de nuevo desde un dispositivo distinto, o la primera vez que configurás el segundo factor.

### Agregado: borrado masivo de contraseñas y "salir" de un recurso compartido

- Se puede seleccionar varias contraseñas a la vez en el Vault y borrarlas juntas, con confirmación.
- Si te compartieron una contraseña que no es tuya, ahora podés sacarla de tu propio Vault sin que la persona dueña tenga que revocarte el acceso — no borra la copia del dueño, sólo la tuya.

### Agregado: mostrar/ocultar contraseña al escribirla

- Los campos de contraseña (login, registro, cambio de contraseña, etc.) ahora tienen un ícono para ver lo que escribiste, en vez de tener que confiar en que no hubo un error de tipeo.

### Agregado: comandos de grupos en `ellkan-cli`

- La línea de comandos ahora puede crear grupos, listarlos, ver el detalle de uno y agregar/quitar miembros — antes había que hacerlo desde la interfaz web sí o sí.
- Se agregó también `ellkan-cli verify-email` (completa la verificación de cuenta desde la CLI) y el login por CLI ya sabe manejar una contraseña provisoria asignada por un admin.

### Arreglado: el panel de administración a veces mostraba "Ocurrió un error" con la sesión bien iniciada

- Algunas páginas del panel de administración (Usuarios, Roles, y otras que comparten la misma ruta que un endpoint real de la API) podían quedar mostrando una versión vieja cacheada por el navegador en vez de los datos reales. Recargar con `Ctrl+Shift+R` lo resolvía momentáneamente, pero el problema podía volver — ya está arreglado de raíz.

### Arreglado: el botón de cerrar sesión podía terminar muy por debajo de la pantalla

- En páginas largas (como el panel de administración), la barra lateral con el botón de cerrar sesión ya no se estira junto con el contenido — queda siempre fija en su lugar.

## [0.1.27] - 2026-08-11

### Agregado: cambio de contraseña obligatorio para cuentas creadas por un admin

- Si un administrador te crea la cuenta, la contraseña temporal que te entrega ahora se tiene que cambiar sí o sí en tu primer inicio de sesión — antes era sólo una recomendación, no algo forzado de verdad.

### Agregado: elegir grupo(s) al crear un usuario

- El formulario de "Crear usuario" del panel de administración ahora deja elegir a qué grupo o grupos incluir a la persona en el mismo paso, en vez de tener que hacerlo después por separado.

### Agregado: sincronización de grupos desde LDAP

- Directory Sync (LDAP) ahora puede traer también la membresía de grupo de cada persona desde el directorio (activable desde su configuración) — si el grupo todavía no existe en Ellkan, se crea solo.
- El filtro de búsqueda de usuarios contra LDAP dejó de estar fijo — ahora se puede configurar para que funcione tanto contra OpenLDAP como contra Active Directory.

### Arreglado: la configuración de Directory Sync perdía el mapeo de atributos al guardar

- El formulario no tenía ningún campo para el mapeo de atributos LDAP → campos de usuario, así que cada vez que se guardaba la configuración se borraba en silencio lo que estuviera configurado. Ahora el formulario tiene esos campos y guardarlo ya no lo pisa.

## [0.1.26] - 2026-08-11

### Agregado: kit de recuperación de cuenta — recuperá tu cuenta vos mismo, sin depender de un administrador

- Al configurar el segundo factor por primera vez (o en el próximo login, si ya tenías uno), ahora se genera un kit de recuperación: un archivo que tenés que guardar en un lugar seguro. Es el único paso obligatorio nuevo — se muestra una vez, con la opción de descargarlo como `.txt` o copiarlo.
- Si te olvidás la contraseña, ya no hace falta esperar a que un admin apruebe tu recuperación: pedís un link por email, elegís una contraseña nueva, pegás tu kit, y confirmás con tu app de autenticación (o con un código por email si todavía no configuraste una). La recuperación vía admin sigue disponible como alternativa para quien no tiene kit.
- Por seguridad, el kit usado para recuperar la cuenta queda invalidado — el próximo inicio de sesión pide generar uno nuevo.
- Se puede generar un kit nuevo en cualquier momento desde Ajustes → Seguridad. Nunca se vuelve a mostrar el kit original, siempre es uno nuevo y distinto.

### Cambiado: recuperación de cuenta por un administrador ahora se puede delegar a admins de grupo

- Aprobar o rechazar una solicitud de recuperación ya no requiere ser admin general de la organización — un admin del grupo de la persona que pide recuperación también puede resolverla. Antes sólo se podía aprobar, nunca rechazar.
- El aviso de una solicitud nueva ya no le llega a todos los admins de la organización, sólo a los del grupo de quien la pidió (con los admins generales como respaldo si esa persona no pertenece a ningún grupo).
- Cada aprobación o rechazo hecho por un admin de grupo queda marcado con claridad en el registro de auditoría, distinto de una acción de un admin general.

## [0.1.25] - 2026-08-11

### Agregado: los grupos ahora son una unidad de trabajo real

- Un usuario sin grupo ya no ve al resto de la organización al buscar con quién compartir; con grupo, sólo ve a su propio grupo (los admins de grupo ven además a otros admins de grupo y al admin general).
- Un admin de grupo puede armar una jerarquía de carpetas propia del grupo (hasta 3 niveles) y compartirla con el grupo entero — cualquier miembro puede agregar contraseñas ahí. Un usuario regular sigue teniendo carpetas planas y 100% personales.
- Al agregar una contraseña a una carpeta de grupo, se puede elegir: mantenerla personal (sólo quien la agregó la edita) o cederla al grupo (cualquier miembro la edita).
- Nuevo: se puede borrar una contraseña de verdad (antes sólo se podía revocar el acceso de alguien, nunca eliminarla). En una carpeta de grupo, sólo puede borrarla el admin de ese grupo o el admin general.
- "Ver todo" en una carpeta ahora también muestra el contenido de sus subcarpetas, con un botón aparte.

### Arreglado

- `/admin/groups` mostraba el ID interno de cada miembro en vez de su nombre.
- El panel de detalle de un recurso SSH/FTP/VNC/Telnet ahora sí sigue el diseño de referencia (Termius) que se había pedido — antes sólo se había agregado el texto del comando, sin el rediseño visual.
- Se puede ver, desde "Mi perfil", a qué grupos pertenece uno y si es admin de alguno.

## [0.1.24] - 2026-08-11

### Agregado: MFA por correo electrónico

Además de la app autenticadora (TOTP), ahora se puede exigir un código de verificación por email como segundo factor de login — el admin elige uno de los dos métodos desde "Política de MFA" (nunca los dos a la vez). El método por correo no necesita ninguna configuración previa del usuario: cada inicio de sesión manda un código nuevo.

### Agregado: avatar en el buscador de "Compartir"

Al buscar con quién compartir un recurso, ahora se ve la foto de perfil real de cada resultado en vez de un ícono genérico.

### Arreglado: mensaje de error al compartir no decía la causa real

El resumen de "Compartir en lote" mostraba siempre el mismo motivo (relacionado a una restricción que ya no existe) sin importar por qué había fallado en realidad. Ahora muestra el motivo real de cada ítem fallido — por ejemplo, si esa persona ya tenía acceso al recurso.

### Cambiado: checkbox de selección más grande

El check para seleccionar recursos en la tabla del Vault ahora es más grande y más fácil de tocar.

## [0.1.23] - 2026-08-11

### Agregado: comando de conexión copiable para SSH/FTP/VNC/Telnet

Al abrir un recurso de tipo SSH, FTP, VNC o Telnet, ahora aparece el comando listo para copiar y pegar en una terminal (por ejemplo `ssh usuario@host -p puerto`). Se agregó Telnet como tipo de recurso nuevo.

### Arreglado: no se podía compartir un recurso "Personal"

Cualquier recurso creado sin que hubiera una clave de metadata compartida quedaba marcado "Personal — no compartible" para siempre, sin ninguna forma de compartirlo con otra persona. Era una restricción innecesaria — se sacó, y ahora cualquier recurso se puede compartir sin importar cómo se haya creado.

## [0.1.22] - 2026-08-10

### Agregado: crear usuarios sin SMTP configurado, y probar la configuración de SMTP desde el navegador

- El panel admin ahora puede crear usuarios aunque todavía no haya SMTP configurado (antes fallaba con "auto-registro no disponible: SMTP no configurado"). La cuenta queda verificada de una, con la misma passphrase temporal que ya se generaba y mostraba al admin.
- `/admin/smtp` ganó un botón de "Probar configuración" que manda un email real de prueba y muestra si llegó — antes había que usar la CLI para saber si la configuración estaba bien.

### Cambiado: página de Política de MFA más clara

- "Métodos permitidos" dejó de ser un campo de texto libre (hoy sólo existe un método real, TOTP) — ahora sólo lo informa.
- "Días de gracia" ganó una explicación de qué controla realmente (no tiene nada que ver con que el código de la app cambie cada 30 segundos).

## [0.1.21] - 2026-08-10

### Agregado: íconos en los botones del Vault

Los botones de "Mover a carpeta", "Agregar tag", "Compartir", "Exportar/Importar" y "Nuevo recurso" ahora tienen un ícono al lado del texto, mismo estilo de línea que ya usaba el menú lateral.

## [0.1.20] - 2026-08-10

### Arreglado: las ventanas de Compartir/Exportar/Nuevo recurso no tenían margen interno real

Encontramos el motivo real de por qué las ventanas nuevas se veían apretadas: tenían un typo en el código que hacía que el margen interno quedara en cero — todo el contenido pegado al borde. Corregido usando como referencia real el mismo sistema de diseño que usan herramientas conocidas (shadcn/ui): más aire adentro, los campos relacionados agrupados en vez de todos separados por igual, y un resalte sutil al hacer foco en un campo (antes no había ninguno).

## [0.1.19] - 2026-08-10

### Arreglado: F5 repetidos podían dejar la app en un estado raro

#### Fixed

- **Recargar la página muchas veces seguidas podía dejar cosas rotas o mostrando "contraseña incorrecta" sin motivo** — el límite general de pedidos por segundo era demasiado ajustado para lo que tarda en cargar `/vault` de una sola vez, y cuando se topaba con ese límite, la app lo interpretaba mal (mostraba "contraseña incorrecta" en vez del error real, y a veces ocultaba de golpe cosas como carpetas o el botón de exportar). Subido el margen y arreglado cómo se interpreta cada error.

### Cambiado: Exportar/Importar y "Nuevo recurso" ahora son ventanas, más pulido visual

#### Changed

- **"Exportar/Importar" y "Nuevo recurso" ahora se abren en una ventana compacta**, igual que "Compartir" — antes, si coincidían abiertos, se apilaban uno debajo del otro empujando toda la pantalla hacia abajo.
- Toque general de pulido en todas las ventanas nuevas: entrada más suave, sombra con más profundidad, esquinas más redondeadas, e íconos de personas/grupos en círculo en vez de sueltos.

## [0.1.18] - 2026-08-10

### Cambiado: "Compartir" de selección múltiple también usa el modal nuevo

El compartir masivo (elegir varias contraseñas y compartirlas todas juntas) ahora usa la misma ventana compacta con buscador en vivo del compartir individual — antes seguía siendo el panel viejo con una caja de texto para pegar emails.

## [0.1.17] - 2026-08-10

### Rediseñado: modal de compartir, más compacto y con buscador en vivo

#### Changed

- **El panel de "Compartir" ahora es una ventana compacta (modal)**, no un panel grande que empujaba el resto de la pantalla hacia abajo — mismo estilo que gestores de contraseñas conocidos: buscador con sugerencias en vivo a medida que escribís el nombre o email, cada persona con acceso en su propia fila con el nivel editable al lado y una cruz para sacarla, y los cambios quedan marcados en naranja hasta que tocás "Guardar" (así podés arrepentirte antes de aplicar nada).

#### Known limitation

- Compartir un recurso con un **grupo** por primera vez todavía no está soportado desde este modal — si un grupo ya tenía acceso, se puede ver/editar/sacar sin problema, pero agregar un grupo nuevo como destinatario queda pendiente para una próxima vuelta.

## [0.1.16] - 2026-08-10

### Arreglado: carpetas no se veían anidadas, y Estado del sistema más completo

#### Fixed

- **Las carpetas dentro de otras carpetas no se veían con sangría** — se mostraban todas al mismo nivel, como una lista plana, en vez de un árbol. Era un error de estilos que afectaba a todos los niveles de anidamiento, no sólo al primero.
- **"Estado del sistema" decía que todo estaba bien aunque no hubiera ninguna clave de metadata compartida creada** — ahora avisa explícitamente cuando falta ese paso (sin él, compartir contraseñas entre usuarios no funciona).

#### Added

- **Estado del sistema** ahora también informa: si hay al menos un administrador activo, y si el cifrado del tráfico (TLS) está siendo manejado por el propio Ellkan.

## [0.1.15] - 2026-08-10

### Arreglado: compartir contraseñas con otros usuarios de la organización

#### Fixed

- **Compartir una contraseña con otro usuario de tu organización directamente ahora funciona de verdad** — antes, ninguna contraseña creada desde la app podía compartirse internamente (sólo aparecía la opción de compartir con alguien externo). Necesitaba tres arreglos encadenados: las contraseñas nuevas ahora nacen "compartibles" cuando corresponde, el administrador ahora puede agregar más personas a la clave organizacional que hace falta para compartir (antes sólo la tenía quien la creó), y se agregó una pantalla para ver y administrar con exactitud quién tiene acceso a cada contraseña compartida.

#### Added

- **Panel de "Compartir" rediseñado**: ahora muestra quién tiene acceso a la contraseña en este momento (con su nivel: lectura, edición o propietario), permite cambiar ese nivel al toque, y sacarle el acceso a alguien con un clic — antes sólo se podía agregar gente, nunca ver ni quitar.
- **Panel de administración de claves de metadata**: nueva opción "Agregar miembro" para sumar a alguien a una clave compartida ya existente, sin tener que rotarla.

## [0.1.14] - 2026-08-10

### Dos arreglos más de uso real: sesión vencida y el cartel de "desbloquear"

#### Fixed

- **Si la sesión vencía por tiempo, la app se quedaba mostrando un error genérico en vez de mandarte a iniciar sesión de nuevo.** Ahora cualquier pantalla te lleva directo al login apenas eso pasa.
- **El cartel que pide la contraseña para desbloquear el vault (no para iniciar sesión, esas son cosas distintas) no explicaba qué estaba pasando** — parecía que se había cerrado la sesión. Ahora usa el mismo cartel claro que ya se usaba en el bloqueo automático por inactividad ("tu sesión sigue activa, sólo hace falta desbloquear"), con las mismas opciones (código local, token de seguridad).

## [0.1.13] - 2026-08-10

### Compartir en lote, TLS sin necesitar un proxy aparte, y arreglo de un bug real de recarga

#### Added

- **Compartir varias contraseñas de una vez**: en el Vault, seleccioná varias contraseñas y compartilas todas con uno o más destinatarios en una sola acción, en vez de una por una.
- **HTTPS sin instalar nada aparte**: Ellkan ahora puede manejar el cifrado del tráfico (HTTPS) él mismo, sin depender de un servidor intermediario extra (nginx u otro) — sólo hace falta indicarle dónde está el certificado. Instrucciones en `manual/instalacion.md`.
- **Nueva guía de instalación**: modos de instalación, cómo hacer y restaurar un backup, problemas comunes y su solución, y una tabla de requisitos mínimos/recomendados de hardware — `manual/instalacion.md`, linkeada desde el README.

#### Fixed

- **Recargar la página (F5) en algunas secciones de administración (Roles, Usuarios, Reportes, Auditoría, Estado del sistema, Claves de metadata, Directory Sync) cerraba la sesión de golpe** — en realidad la sesión seguía viva, era un problema de enrutamiento interno del servidor (esas URLs eran, por casualidad, también rutas internas de la API). Arreglado sin tocar ninguna URL existente.

## [0.1.12] - 2026-08-10

### Matriz visual de permisos para roles

#### Added

- **Roles personalizados, ahora visuales**: la pantalla de administración de roles ya no obliga a escribir permisos a mano en una lista de texto — ahora es una tabla agrupada por categoría (gestión de grupos, importar/exportar, ver/copiar contraseñas, carpetas, compartir) con un selector "Permitir/Denegar" por cada permiso y cada rol, igual de fácil de leer que de cambiar.
- **Delegar la creación de grupos**: ahora se puede crear un rol al que sólo se le permite crear grupos, sin darle acceso de administrador completo — antes esto sólo lo podía hacer un admin de la organización.

#### Changed

- El estado de "sos admin" que usa la app para mostrar/ocultar el panel de administración ahora se resuelve con un endpoint dedicado en vez de un truco (probar un endpoint de admin y ver si rechaza el acceso).

## [0.1.11] - 2026-08-10

### Carpetas con permisos reales, grupos por CSV, dispositivos de confianza, y más

#### Added

- **Carpetas**: ahora se pueden mover contraseñas dentro de una carpeta (antes las carpetas sólo servían para organizar otras carpetas). Las carpetas también se pueden compartir con otra persona con un nivel de acceso (lectura, edición o propietario) — como en cualquier gestor de contraseñas serio, mover algo a una carpeta compartida no le da acceso automático a nadie: compartir el contenido en sí sigue siendo un paso aparte, explícito. Clic en una carpeta ahora filtra la lista de contraseñas por su contenido.
- **Grupos**: agregar un miembro ahora tiene un buscador con autocompletado en vez de tener que escribir el email de memoria, y se puede cargar una lista completa desde un archivo CSV en vez de agregar de a uno.
- **Dispositivos de confianza**: nueva pantalla en "Mi cuenta → Seguridad" para ver y revocar los dispositivos marcados como confiables (esto ya existía por dentro, pero no había ninguna forma de gestionarlo).
- **Tipos de contraseña nuevos**: FTP, SSH y VNC, además del tipo usuario/contraseña de siempre.
- **Compartir más visible**: ahora hay un ícono de compartir directo en cada fila de la lista, no hace falta abrir el detalle de la contraseña primero.
- **Selección múltiple en el Vault**: además de exportar, ahora se puede mover varias contraseñas seleccionadas a una carpeta o agregarles un tag, todo de una vez.
- **Panel de usuarios más completo**: la lista de usuarios ahora muestra el avatar, a qué grupos pertenece cada uno, y cuántas contraseñas propias y compartidas tiene. También se puede activar/desactivar varios usuarios a la vez.

## [0.1.10] - 2026-08-10

### Recuperación de cuenta con pantallas reales, y auto-registro configurable

#### Added

- **Recuperación de cuenta**: ahora hay una pantalla real para recuperar el acceso si perdés tu contraseña (antes sólo existía la configuración, sin ninguna forma de usarla). Desde "Mi cuenta → Seguridad" podés habilitarla; si más adelante perdés tu contraseña, un enlace nuevo en la pantalla de inicio de sesión ("¿Olvidaste tu contraseña?") te lleva al flujo de recuperación, que queda pendiente de que un administrador lo apruebe. Los administradores ahora ven un listado de solicitudes pendientes con botón de aprobar, en la misma pantalla donde ya se configuraba la política.
- **Auto-registro configurable**: nueva sección de administración para decidir si cualquiera puede crear una cuenta sola, restringirlo a ciertos dominios de correo (por ejemplo, sólo `@netics.cl`), o desactivarlo por completo. Si está activado, cualquier cuenta nueva (salvo la primera de la instancia) tiene que verificar su correo con un código de 6 dígitos antes de poder iniciar sesión — si el correo saliente no está configurado, el auto-registro queda bloqueado en vez de emitir códigos que nunca llegarían.

## [0.1.9] - 2026-08-10

### Reorganización de la cuenta personal y exportación

#### Changed

- "Mi perfil", "Preferencias" y "Seguridad" se unificaron en una sola sección "Mi cuenta" con su propio menú interno, en vez de tres accesos sueltos en el menú principal — y de paso, "Mi perfil" dejó de obligar a hacer scroll largo para llegar a una opción puntual.
- El pie del menú ahora muestra tu avatar, tu nombre y tu correo (antes sólo el correo).
- Exportar/Importar se sacó de "Configuración" y ahora vive directamente en el Vault, junto a las contraseñas que exporta. Se puede elegir exportar todos los recursos o sólo los que selecciones con los nuevos casilleros de la tabla.

## [0.1.8] - 2026-08-09

### Primera ronda de correcciones tras uso real

#### Fixed

- Recargar la página (F5) ya no cierra la sesión — antes forzaba a iniciar sesión de nuevo por completo; ahora se comporta como el bloqueo automático (sólo hay que reingresar la contraseña).
- Varios botones que quedaban desalineados respecto al campo de texto de al lado (carpetas, tags, reportes, auditoría, grupos, usuarios).
- El botón para crear una carpeta nueva quedaba tapado por el panel de al lado.
- El registro de auditoría mostraba un identificador interno en vez del nombre/correo de quien hizo cada acción, y la fecha en un formato poco legible.
- Subir el límite de tamaño del avatar a 2 MB no funcionaba correctamente sin un ajuste adicional en el servidor — ya corregido.

#### Changed

- "Estado del sistema": se sacó la versión de la aplicación y la cantidad de migraciones como datos destacados (no aportaban nada útil) y se agregó una verificación real y nueva sobre si el sistema está configurado para HTTPS. Las integraciones opcionales sin configurar ya no aparecen en verde como si todo estuviera bien — aparecen en un color neutro, distinto de "todo en orden".
- Ya no aparecen referencias a códigos internos de desarrollo (como "F-03") en los textos que ve cualquier usuario.
- "Retención de datos" ahora explica qué se borra exactamente (sólo contenido ya eliminado por el propio usuario, nunca datos activos).
- El logo en la pantalla de inicio de sesión es más grande y visible.
- Se puede copiar el usuario y la URL de una contraseña directo desde su panel de detalle, no sólo la contraseña en sí.

## [0.1.7] - 2026-08-09

### Panel de administración reorganizado, autodiagnóstico, y "Mi perfil"

#### Added

- Nueva sección en el panel de administración que muestra el estado general del sistema (base de datos, correo saliente, integraciones, seguridad) con un semáforo por cada verificación y una sugerencia de cómo resolverlo si algo no está del todo bien.
- El menú del panel de administración ahora agrupa sus secciones por categoría en vez de mostrar una única lista plana, para ubicarlas más rápido.
- El primer usuario que se registra en una instancia sin ningún usuario todavía queda como administrador automáticamente, sin pasos adicionales.
- Nueva sección "Mi perfil": ver tu información de cuenta (nombre, email, rol, fechas), subir o quitar una foto de perfil, ver la huella digital de tus claves de cifrado, y cambiar tu contraseña maestra de verdad (antes no existía forma de hacerlo desde la aplicación).
- Nuevo "token de seguridad" personal (un color y una palabra que elegís vos) que se muestra antes de pedirte la contraseña en este dispositivo — si alguna vez no aparece o no coincide, es señal de que algo no está bien.

#### Fixed

- La imagen de Docker no compilaba (`docker compose up` fallaba en el paso de build del backend) por un caché interno desactualizado, sin relación con ninguna funcionalidad visible — corregido.

#### Known limitations

- Igual que el resto de la aplicación, ninguna de las secciones nuevas se probó todavía con interacción real de mouse/teclado en un navegador.
- El primer-usuario-administrador sólo aplica al próximo registro en una instancia sin usuarios — una cuenta ya registrada no se vuelve administrador retroactivamente sólo por reconstruir la aplicación.
- Cambiar la contraseña cierra todas las sesiones activas, incluida la que hizo el cambio — es intencional (misma lógica que un cambio de contraseña en cualquier otra aplicación), pero significa que hay que iniciar sesión de nuevo enseguida.
- El token de seguridad se guarda sólo en este navegador/dispositivo — un dispositivo nuevo no lo va a mostrar hasta que lo generes ahí también.

## [0.1.6] - 2026-08-08

### Cierre de Fase 1 (backend + frontend web)

#### Added

- Inicio de sesión único y sincronización de directorio verificados de punta a punta contra un proveedor de identidad y un servidor LDAP reales.
- Envío real de notificaciones por email (antes sólo se encolaban internamente).
- Listado completo y paginado de usuarios en el panel de administración.
- Edición de un recurso ya guardado, con protección contra que dos ediciones simultáneas se pisen entre sí.
- Reportes operativos: contraseñas vencidas, cobertura de doble factor, usuarios inactivos, y recursos nunca actualizados desde su creación.
- Al agregar un miembro nuevo a un grupo que ya tiene recursos compartidos, ese miembro recibe acceso real a esos recursos de inmediato.
- La vista de recursos ya no se recarga por completo si no hubo cambios reales al volver a la pestaña.

#### Fixed

- Corrida completa de la suite de pruebas del backend: un conflicto entre dos librerías de cifrado de red hacía fallar cualquier conexión segura en ciertas combinaciones — corregido fijando una única implementación de forma explícita al arrancar.

#### Known limitations

- Editar un recurso todavía sólo funciona para recursos personales, no para los compartidos por metadata organizacional.
- El reporte de "contraseñas vencidas" usa la fecha de alta de la cuenta como referencia, porque todavía no existe una función real de rotación de contraseña.
- Ningún flujo de la aplicación web se probó todavía con interacción real de mouse/teclado en un navegador — toda la verificación de esta fase fue automatizada contra el backend real o revisión exhaustiva de código, nunca clicks manuales ni simulados.

## [0.1.5] - 2026-08-07

### Passkeys sin contraseña, exportación personal, y respaldo del sistema

#### Added

- Las passkeys que lo soportan ahora permiten iniciar sesión sin volver a escribir la passphrase, además de poder listarse y revocarse individualmente.
- Página pública para compartir un secreto con alguien sin cuenta en el sistema.
- Exportación e importación personal de contraseñas en los formatos KDBX (KeePass), CSV y CXF (estándar abierto de intercambio de credenciales), con medidor de fortaleza para la contraseña que protege el archivo.
- Respaldo cifrado de la instancia completa y restauración verificada contra una base de datos limpia, desde línea de comandos.
- Exportación masiva de usuarios y grupos para migraciones administrativas, sin exponer ningún dato criptográfico.

#### Known limitations

- El formato CXF exportado no se probó contra otros gestores de contraseñas reales, sólo contra sí mismo.

## [0.1.4] - 2026-08-06

### Seguridad organizacional (cierre de 1.3)

#### Added

- Políticas de MFA organizacional con TOTP: usuario sin segundo factor configurado no puede operar hasta configurar uno, vínculo criptográfico entre el desafío de MFA y la sesión.
- Políticas de longitud/entropía de passphrase a nivel organización.
- Recuperación de cuenta con custodia y aprobación por umbral de administradores.
- Acceso de emergencia entre pares (designar, aceptar, solicitar, aprobar, o resolución automática por tiempo agotado).
- Retención y purga automática de datos vencidos, sin tocar el registro de auditoría.
- Borrado de usuario atómico con verificación previa de bloqueos (único administrador de grupo o único propietario de un recurso) y transferencia obligatoria antes de purgar.
- Desactivación de usuario que invalida de inmediato cualquier sesión ya abierta.
- Inicio de sesión único vía OpenID Connect, vinculado por email verificado del proveedor de identidad.
- Aprovisionamiento automático de usuarios vía SCIM 2.0.
- Sincronización de directorio LDAP con modo de simulación (dry-run) antes de aplicar cambios.

#### Fixed

- Un test de la CLI (F-35, Fase 0) fallaba de forma reproducible por reutilización de conexión HTTP keep-alive en el servidor de prueba simulado — no era un bug del cliente real, sólo del doble de prueba.

#### Known limitations

- Verificación de SSO OIDC y de Directory Sync LDAP contra un proveedor real (Keycloak/OpenLDAP) sigue pendiente por falta de esa infraestructura de prueba en esta máquina — el código y los tests ya están escritos contra la ceremonia real de cada protocolo, ver `docs/pendientesVerificacionReal.md`.

## [0.1.3] - 2026-08-04

### Audit log

#### Added

- Registro de auditoría inmutable de eventos de seguridad relevantes: inicios de sesión exitosos y fallidos, verificación de dispositivo nuevo, cierre de sesión, otorgamiento de acceso a un recurso, altas y bajas de miembros de grupo y cambios de administrador de grupo, creación de recursos, confianza y revocación de dispositivos, aprobación de inicio de sesión desde otro dispositivo, cambios de política de aprobación de dispositivos, y cambios administrativos de roles y de la clave de metadata compartida.
- Lectura paginada del registro con filtros por actor, tipo de evento y rango de fechas, y exportación en NDJSON o CSV pensada para alimentar un colector externo (SIEM).
- Permiso de sólo lectura para el registro de auditoría, separado del rol de administrador completo, para poder delegar la función de auditoría sin dar control total del sistema.

#### Fixed

- Dos endpoints (gestión de dispositivos de confianza y administración de roles) devolvían las fechas de creación/revocación en un formato interno no legible en vez de una fecha estándar.

#### Known limitations

- El bloqueo de modificación/borrado del registro se aplica hoy con una restricción a nivel de base de datos, no todavía con un rol de conexión separado del que administra el esquema — queda pendiente para cuando exista esa separación de infraestructura.
- Todavía no cubre eventos de políticas de doble factor, políticas de contraseña, recuperación de cuenta con custodia ni acceso de emergencia — llegan con los próximos cambios de esta misma área.

## [0.1.2] - 2026-08-03

### Passkeys y dispositivos de confianza

#### Added

- Login sin passphrase vía passkeys (WebAuthn): ceremonia de registro y autenticación completas, con soporte opcional para la extensión PRF (guardada como blob opaco, nunca calculada ni interpretada por el servidor).
- Login desde un dispositivo nuevo aprobado por un dispositivo de confianza ya existente ("login with device"): solicitud de aprobación, comparación de huella entre ambos dispositivos, aprobación, y alta automática del dispositivo nuevo como confiable.
- Gestión de dispositivos de confianza: listado, marcado del dispositivo actual como confiable, revocación.
- Política organizacional para habilitar/deshabilitar los métodos de aprobación de dispositivo.

#### Known limitations

- La aprobación de un dispositivo nuevo por parte de un administrador (en vez de por un dispositivo propio del usuario) todavía no tiene un mecanismo funcional — sólo existe el interruptor de política, apagado por defecto. Depende de un mecanismo de recuperación de cuenta con custodia que todavía no está implementado.
- El listado de dispositivos sólo muestra los dispositivos marcados como confiables, no los dispositivos simplemente "conocidos" del historial de inicios de sesión.

## [0.1.1] - 2026-08-02/03

### Organización de recursos

#### Added

- Sistema mínimo de roles (administrador / usuario / auditor) con endpoints de administración.
- Carpetas con vista propia por usuario (mover una carpeta no afecta lo que ven otros usuarios con acceso al mismo contenido).
- Tags personales (privados) y compartidos (con permiso de administrador para crearlos), con filtro de recursos por tag.
- Clave de metadata compartida a nivel organización, con envoltura individual por destinatario autorizado.
- Rotación de la clave de metadata compartida con ventana de superposición entre la clave saliente y la entrante, sin interrupción de servicio.
- Grupos jerárquicos con administradores delegados por grupo y subgrupos, sin herencia de acceso entre padre e hijo.
- Tipo de recurso con segundo factor TOTP embebido junto a la contraseña.

#### Known limitations

- El re-cifrado de un recurso durante una rotación de clave de metadata lo tiene que disparar un cliente con acceso real al contenido (el servidor nunca ve la metadata en claro) — sin un cliente que lo haga, un recurso que nadie edita puede quedar pendiente de forma indefinida.
- La validación de profundidad máxima al mover un grupo es por-grupo, no recalcula la profundidad de todo el árbol que se movería junto con él.
- El sistema de roles cubre sólo lo mínimo necesario (un permiso de "administrador total"); permisos administrativos granulares quedan para más adelante.

## [0.1.0] - 2026-08-02

### Núcleo criptográfico, backend y CLI

#### Added

- Núcleo criptográfico (generación de pares de claves, derivación desde passphrase, cifrado autenticado, sellado de claves por destinatario, TOTP) compilable a nativo y a WebAssembly.
- Registro e inicio de sesión sin contraseña en tránsito (prueba de posesión de clave privada mediante firma), con verificación de dispositivo nuevo por correo.
- Creación, lectura y compartición básica de recursos cifrados.
- CLI con inyección segura de secretos en subprocesos, redirecciones HTTP restringidas, mTLS opcional y filtro de expresiones para listados.
