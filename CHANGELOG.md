# Changelog

Autor: Athan Espinoza

Registro de cambios de Ellkan. Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/), con una salvedad: el número de versión de cada entrada es un contador propio de este archivo, uno por fase de implementación cerrada — **no** corresponde a la versión real del paquete en `Cargo.toml` (que sigue fija en `0.1.0` hasta el primer release etiquetado de v1).

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
