# Manual de referencia — funcionalidades

Qué hace Ellkan hoy, organizado por área. Para instalar/levantar el sistema ver el [README](../README.md); para la CLI, ver [cli.md](cli.md).

## Cuenta y acceso

- **Registro y login sin contraseña en tránsito**: el keypar (X25519 + Ed25519) se genera en tu dispositivo; el login es una firma de un desafío del servidor, nunca viaja una contraseña por la red.
- **Verificación de dispositivo nuevo por email**: el primer login desde un dispositivo no reconocido pide un código de 6 dígitos enviado por email antes de completar la sesión — aplica a cualquier usuario, incluido el primero.
- **Passkeys (WebAuthn)**: alta y login sin volver a escribir la passphrase. Si el autenticador soporta la extensión PRF, la clave privada se desbloquea directo con la passkey; si no, la passkey sólo reemplaza el paso de login y la passphrase se sigue pidiendo para operar sobre recursos.
- **Login desde un dispositivo nuevo aprobado por uno de confianza** ("login with device"): compara una huella corta entre ambos dispositivos antes de aprobar — evita re-tipear la passphrase sin transmitirla nunca.
- **Desbloqueo rápido local con TOTP**: un código de 6 dígitos generado localmente reemplaza la passphrase completa en un dispositivo puntual, sin tráfico de red — se configura por dispositivo, revocable individualmente.
- **Auto-bloqueo por inactividad y limpieza de portapapeles**, con techos opcionales fijables por política organizacional.

## Vault

- **Recursos login/contraseña**, con TOTP embebido opcional (segundo factor guardado junto a la contraseña, no reemplaza el MFA de login).
- **Generador de contraseñas** integrado en crear/editar, siguiendo la política de longitud y charset de la organización.
- **Carpetas** con vista propia por usuario (moverla no afecta lo que ven otros con acceso al mismo contenido) y **tags** personales o compartidos, con filtro combinable.
- **Búsqueda** por nombre, usuario o URI sobre lo ya cargado.
- **Editar un recurso ya creado** — funciona tanto para recursos personales (`user_key`) como compartidos (`shared_key`); en este último caso re-cifra la metadata con la clave de metadata compartida y re-sella el secreto para todos los destinatarios actuales.
- **Compartir un recurso** con otro usuario de la organización (sólo recursos de tipo compartible).
- **Compartir externo** (`/s/{id}`): genera un link de un solo uso (o hasta N vistas) para alguien sin cuenta en Ellkan, con expiración configurable y contraseña adicional opcional. El servidor sólo guarda un blob cifrado — la clave vive en el fragmento de la URL, que nunca se manda al servidor.

## Organización

- **Grupos jerárquicos** con administradores delegados por grupo, subgrupos, sin herencia automática de acceso entre padre e hijo.
- **Clave de metadata compartida** a nivel organización, con rotación con ventana de superposición (sin interrupción de servicio mientras dura la migración).
- **Roles**: administrador, usuario, auditor (sólo lectura del audit log) — permiso administrativo total como unidad mínima hoy, sin granularidad más fina.

## Seguridad organizacional (configurable en el panel de administración)

- Política de MFA (TOTP obligatorio u opcional, días de gracia).
- Política de contraseña/passphrase (longitud, entropía mínima, reglas del generador).
- Retención y purga automática de datos vencidos (nunca toca el audit log).
- Recuperación de cuenta con custodia y aprobación por umbral de administradores.
- Acceso de emergencia entre pares (designar un contacto de confianza, solicitar, aprobar, o resolución automática por tiempo agotado).
- Política de aprobación de dispositivo nuevo (email vs. dispositivo de confianza).
- Política de Compartir Externo (habilitar/deshabilitar, expiración máxima, exigir contraseña adicional).
- Política de exportación (habilitar/deshabilitar por organización, con excepción para admins, formatos permitidos).

## Federación e identidad externa

- **SSO** vía OpenID Connect, vinculado por email verificado del proveedor.
- **SCIM 2.0** para aprovisionamiento automático de usuarios desde un IdP externo.
- **Directory Sync (LDAP)** con modo simulación (dry-run) antes de aplicar cambios.

Los tres requieren un proveedor externo real configurado (Keycloak, Azure AD, OpenLDAP, etc.) — el código y los tests están verificados contra infraestructura real, pero configurar tu propio IdP es responsabilidad del operador.

## Auditoría y reportes

- **Audit log inmutable** (no se puede editar ni borrar ni con acceso directo a la base) de eventos de seguridad: logins, verificación de dispositivo, cambios de grupo, creación de recursos, rotación de claves, cambios administrativos, y más. Filtrable por actor/tipo/fecha, exportable en NDJSON o CSV.
- **Reportes operativos**: contraseñas vencidas, cobertura de MFA, usuarios inactivos, recursos nunca actualizados.

## Exportación, importación y backup

- **Exportación/importación personal** en KDBX (KeePass), CSV y CXF (Credential Exchange Format), con medidor de fortaleza para la contraseña que protege el archivo.
- **Backup cifrado de la instancia completa** y restauración, vía CLI (`age`, streaming — ver [cli.md](cli.md)).
- **Exportación masiva de usuarios y grupos** para migraciones administrativas, sin exponer dato criptográfico alguno.

## Administración

Panel web con ~19 secciones: usuarios, roles, grupos, audit log, reportes, y una pantalla por política (MFA, contraseña, retención, recuperación de cuenta, acceso de emergencia, aprobación de dispositivo, exportación, compartir externo), configuración de SMTP, más SSO/SCIM/Directory Sync y claves de metadata.

**El primer login de cualquier usuario desde un dispositivo nuevo exige un código por email** (F-02). **Si SMTP no está configurado, ese dispositivo se marca conocido automáticamente** (evento `auth.device_auto_verified_no_smtp` en el audit log, con warning en el log del servidor) en vez de bloquear para siempre — nadie queda encerrado afuera por falta de SMTP, ni el primer admin ni nadie más. En cuanto se configura un SMTP real, el próximo dispositivo nuevo de cualquier cuenta vuelve a pedir verificación de verdad — este auto-verify no es un interruptor global, se resuelve por intento de login. La config de SMTP vive cifrada en la base de datos (`/admin/smtp` en el panel, o `PUT /admin/smtp-config`; reemplaza el viejo esquema `ELLKAN_SMTP_*` por variable de entorno). Para el primer admin, `ellkan-cli admin create-user --role admin` (ver [cli.md](cli.md)) además marca ese dispositivo puntual como conocido de entrada, sin depender siquiera de este fallback. Usar `ellkan-cli admin send-test-email` para confirmar que la config de SMTP quedó bien una vez cargada.

## Internacionalización y accesibilidad visual

- Español e inglés, cambiable en cualquier momento sin perder sesión.
- Tema claro/oscuro, con transición animada al cambiar.
- Paleta densa y funcional pensada para uso prolongado, sin decoración fuera de los acentos de marca.

## Qué todavía no existe

Documentado acá para que no se asuma construido:

- **Self-registration abierto** — hoy el alta de cuentas es siempre explícita (formulario de registro con invitación implícita o bootstrap por CLI), no hay un flujo de "cualquiera se registra solo" configurable.
- **Remember Me** (sesión extendida más allá de lo que dura hoy).
- **Modo `serve` de la CLI** (servidor HTTP local para integraciones).
- **RBAC granular** más allá de admin/usuario/auditor.
