# Changelog

Autor: Athan Espinoza

Registro de cambios de Ellkan. Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/), con una salvedad: el número de versión de cada entrada es un contador propio de este archivo, uno por fase de implementación cerrada — **no** corresponde a la versión real del paquete en `Cargo.toml` (que sigue fija en `0.1.0` hasta el primer release etiquetado de v1).

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
