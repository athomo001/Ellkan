# Changelog

Autor: Athan Espinoza

Registro de cambios de Ellkan. Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/), con una salvedad: el número de versión de cada entrada es un contador propio de este archivo, uno por fase de implementación cerrada — **no** corresponde a la versión real del paquete en `Cargo.toml` (que sigue fija en `0.1.0` hasta el primer release etiquetado de v1).

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
