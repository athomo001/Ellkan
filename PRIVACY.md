# Privacidad / Privacy

**Autor:** Athan Espinoza

*English version below.*

## Resumen

- **El autor de Ellkan no recibe ningún dato.** El software no tiene telemetría, analítica ni "llamadas a casa".
- **Cada instancia la opera quien la instala** (una empresa, un equipo o una persona). Ese operador es el responsable de los datos que guarda su servidor: los pedidos sobre tus datos (acceso, corrección, borrado) se le hacen a él.
- **El contenido de la bóveda viaja y se guarda cifrado de punta a punta.** Nombres, URLs, usuarios, contraseñas, notas y códigos TOTP se cifran en tu dispositivo; el servidor guarda sólo texto cifrado que no puede leer.

## Qué guarda un servidor de Ellkan

| Dato | Para qué | Cifrado de punta a punta |
|---|---|---|
| Contenido de la bóveda (nombres, URLs, usuarios, contraseñas, notas, TOTP) | Sincronizar y compartir | Sí |
| Tu material de claves (clave privada sellada con tu passphrase) | Que puedas abrir la bóveda desde otro dispositivo | Sí |
| Email, nombre visible y foto de perfil (opcional) | Identificarte, avisos por correo, compartir | No |
| Grupos, carpetas compartidas y quién tiene acceso a qué recurso | Permisos | No (los nombres de los recursos sí están cifrados) |
| Dispositivos y sesiones (etiqueta, primera y última vez visto) | Seguridad de la cuenta | No |
| Registro de auditoría (quién hizo qué acción y cuándo) | Seguridad y cumplimiento; retención por defecto 365 días, configurable por el operador | No |
| Correos salientes | Envío; el cuerpo se borra al enviarse y la fila se purga a los 7 días | No |

**Excepción a conocimiento cero:** si el operador activa la *recuperación de cuenta aprobada por administradores*, quienes administren esa instancia pueden, con la aprobación requerida, devolverte el acceso a tu bóveda. Esa función es opcional y la interfaz lo avisa al activarla.

**Dirección IP:** no se guarda en la base de datos. Los logs del servidor sólo la incluyen cuando una solicitud se rechaza por exceso de solicitudes (para detectar abuso); cuánto tiempo se conservan esos logs depende del operador.

## Servicios de terceros

Ellkan sólo se conecta con servicios externos en estos casos:

- **Correo (SMTP), inicio de sesión único (SSO/OIDC), LDAP y SCIM:** sólo los que configure el operador de la instancia.
- **Have I Been Pwned (opcional, apagado por defecto):** para avisar si una contraseña aparece en filtraciones. Se envían sólo los primeros 5 caracteres del hash SHA-1 de la contraseña (modelo *k-anonymity*); ni el servicio ni Ellkan ven la contraseña.
- **Íconos de sitios en la extensión:** **apagado por defecto**: el popup muestra la inicial de cada sitio y no se conecta a nadie. Si activás «Íconos de los sitios» (Mi cuenta, en el popup), pide el ícono de cada sitio al servicio de favicons de Google con el **nombre del dominio** (por ejemplo `github.com`); nunca usuarios, contraseñas ni la ruta completa.
- **Telemetría para el operador (OpenTelemetry):** apagada por defecto. Si el operador la activa, los datos van a su propio colector, nunca al autor, y no incluyen encabezados, cuerpos de solicitudes ni consultas SQL.

## Qué queda en tu dispositivo

- **Navegador (web):** una caché de la bóveda en IndexedDB, cifrada con una clave que vive sólo mientras la pestaña está abierta (`sessionStorage`); la clave del desbloqueo rápido si lo activás; y preferencias de interfaz (`localStorage`).
- **Extensión:** el estado de la sesión en `storage.session`, que el navegador borra al cerrarse; si activás el desbloqueo rápido, su estado cifrado en `storage.local` y una clave no exportable en IndexedDB. Sus permisos: acceso a los sitios para detectar formularios de login y completar credenciales; `storage`, `alarms` e `idle` para el bloqueo automático; `nativeMessaging` para hablar con la app de escritorio.
- **App de escritorio:** la bóveda local cifrada (SQLite), su configuración y un log de diagnóstico sin secretos, con tope de tamaño.

## Contacto

Para dudas sobre el software, abrí un issue en el repositorio. Para datos guardados en una instancia, contactá a su operador. Vulnerabilidades: ver [SECURITY.md](SECURITY.md).

---

## English

### Summary

- **The author of Ellkan receives no data.** The software has no telemetry, analytics or "phone home".
- **Each instance is run by whoever installs it** (a company, a team or an individual). That operator is responsible for the data on their server: requests about your data (access, correction, deletion) go to them.
- **Vault contents are end-to-end encrypted.** Names, URLs, usernames, passwords, notes and TOTP codes are encrypted on your device; the server stores only ciphertext it cannot read.

### What an Ellkan server stores

| Data | Purpose | End-to-end encrypted |
|---|---|---|
| Vault contents (names, URLs, usernames, passwords, notes, TOTP) | Sync and sharing | Yes |
| Your key material (private key sealed with your passphrase) | Opening the vault from another device | Yes |
| Email, display name and profile picture (optional) | Identifying you, email notices, sharing | No |
| Groups, shared folders and who can access which item | Permissions | No (item names are encrypted) |
| Devices and sessions (label, first and last seen) | Account security | No |
| Audit log (who did which action and when) | Security and compliance; 365-day default retention, configurable by the operator | No |
| Outgoing emails | Delivery; the body is erased once sent and the row is purged after 7 days | No |

**Zero-knowledge exception:** if the operator enables *administrator-approved account recovery*, the administrators of that instance can, with the required approval, restore your access to your vault. It is optional and the interface warns about it when enrolling.

**IP address:** not stored in the database. Server logs only include it when a request is rejected for exceeding the rate limit (to detect abuse); how long those logs are kept is up to the operator.

### Third-party services

Ellkan only contacts external services in these cases:

- **Email (SMTP), single sign-on (SSO/OIDC), LDAP and SCIM:** only those the instance operator configures.
- **Have I Been Pwned (optional, off by default):** to warn about passwords found in breaches. Only the first 5 characters of the password's SHA-1 hash are sent (*k-anonymity*); neither the service nor Ellkan sees the password.
- **Site icons in the extension:** **off by default**: the popup shows each site's initial and contacts no one. If you turn on "Íconos de los sitios" (site icons, under My account in the popup), it requests each site's icon from Google's favicon service using the **domain name** (e.g. `github.com`); never usernames, passwords or full paths.
- **Operator telemetry (OpenTelemetry):** off by default. If the operator enables it, data goes to their own collector, never to the author, and excludes headers, request bodies and SQL queries.

### What stays on your device

- **Browser (web):** a vault cache in IndexedDB, encrypted with a key that only lives while the tab is open (`sessionStorage`); the quick-unlock key if you enable it; and interface preferences (`localStorage`).
- **Extension:** session state in `storage.session`, which the browser clears on exit; if you enable quick unlock, its encrypted state in `storage.local` and a non-exportable key in IndexedDB. Its permissions: site access to detect login forms and fill credentials; `storage`, `alarms` and `idle` for auto-lock; `nativeMessaging` to talk to the desktop app.
- **Desktop app:** the encrypted local vault (SQLite), its settings and a size-capped diagnostic log without secrets.

### Contact

For questions about the software, open an issue in the repository. For data stored on an instance, contact its operator. Vulnerabilities: see [SECURITY.md](SECURITY.md).
