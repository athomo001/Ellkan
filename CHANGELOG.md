# Changelog

Autor: Athan Espinoza

Registro de cambios de Ellkan. Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/), con una salvedad: el número de versión de cada entrada es un contador propio de este archivo, uno por fase de implementación cerrada — **no** corresponde a la versión real del paquete en `Cargo.toml` (que sigue fija en `0.1.0` hasta el primer release etiquetado de v1).

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
