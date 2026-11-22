# Plantilla de política de privacidad para una instancia de Ellkan

**Autor:** Athan Espinoza

> **Esto es una plantilla, no asesoría legal.** Quien opera la instancia (tu empresa u organización) es responsable de los datos que guarda y de su política de privacidad. Completá lo que está entre `[corchetes]`, borrá lo que no aplique y hacela revisar por alguien que conozca la ley que te toca (por ejemplo, la Ley 19.628 o la 21.719 en Chile, o el GDPR en la UE). Cuando esté publicada, cargá su dirección en **Administración → Políticas → Textos legales** para que el registro y el login la muestren.

---

## Política de privacidad de [nombre del servicio]

**Última actualización:** [fecha]

### 1. Quién es responsable

[Nombre de la organización], [domicilio], es responsable de los datos personales de este servicio de gestión de contraseñas (en adelante, «el servicio»). Contacto para temas de privacidad: [correo o formulario]. [Si corresponde: delegado de protección de datos: nombre y contacto.]

### 2. Qué datos tratamos y cuáles no podemos ver

El servicio usa Ellkan, un gestor de contraseñas con cifrado de extremo a extremo: **el contenido de tu bóveda se cifra en tu dispositivo** y nosotros no podemos leerlo.

| Dato | ¿Podemos leerlo? |
| --- | --- |
| Contraseñas, notas, secretos, nombres, usuarios y URLs de tus recursos, nombres de carpetas | **No.** Están cifrados con claves que sólo tenés vos (y quien elijas al compartir). |
| Tu clave privada | **No.** Está cifrada con tu contraseña maestra, que nunca recibimos. |
| Correo electrónico, nombre visible y foto de perfil | Sí. |
| Nombres de grupos y etiquetas, membresías, fechas, a quién compartiste un recurso | Sí. |
| Registro de auditoría (quién hizo qué y cuándo, nunca el contenido) | Sí, el personal administrador y auditor. |
| Correos que te envía el servicio | Sí, mientras se envían; se borran [7 días] después. |
| Tu dirección IP | Sólo en memoria, unos segundos, para limitar intentos de acceso; no se guarda. [Si tu proxy o firewall la registra, decilo acá.] |

### 3. Para qué los usamos y con qué base

- **Darte el servicio** (crear tu cuenta, iniciar sesión, compartir con tu equipo): [base legal, por ejemplo: ejecución del contrato de trabajo o de servicio].
- **Seguridad** (registro de auditoría, límites de intentos, avisos de inicio de sesión): [interés legítimo / obligación legal].
- **Comunicaciones del servicio** (códigos de verificación, avisos de acceso de emergencia o de recuperación de cuenta): [ejecución del contrato].

No usamos tus datos para publicidad ni los vendemos.

### 4. Con quién se comparten

- **Proveedor de correo** [nombre del servidor SMTP o proveedor], para enviar los correos del servicio.
- [Si se configuró inicio de sesión con la organización (SSO): **proveedor de identidad** [nombre], que confirma quién sos.]
- [Si se sincroniza un directorio (LDAP/Active Directory) o SCIM: de dónde vienen los usuarios y grupos.]
- [Proveedor de alojamiento o nube: nombre y país.]
- El servicio **no se conecta a terceros por su cuenta**. [Si un administrador activó el aviso de versión nueva: una vez al día consulta el número de la última versión en GitHub, sin enviar datos tuyos.]

[Si hay transferencias fuera del país: a dónde y con qué garantías.]

### 5. Cuánto tiempo se guardan

- Cuenta y bóveda: mientras la cuenta exista. Al borrarla, sus datos se eliminan [en el momento / tras N días].
- Elementos borrados de la bóveda: [N días] en la papelera y después se eliminan.
- Registro de auditoría: [365 días] (configurable).
- Correos enviados: [7 días].
- Copias de seguridad: [frecuencia y cuánto se conservan].

### 6. Tus derechos

Podés pedir acceso, rectificación, eliminación, oposición, portabilidad [y los demás que reconozca tu ley] escribiendo a [contacto]. Respondemos en [plazo].

- **Ver qué datos tuyos tenemos:** en **Mi perfil → Mis datos personales** descargás un archivo con todo lo que el servidor sabe de tu cuenta.
- **Exportar tu bóveda:** lo podés hacer vos desde la aplicación (CSV, KeePass), salvo que la política de la organización lo restrinja.
- **Eliminar tu cuenta:** [cómo pedirlo]. Algunas entradas del registro de auditoría se conservan por [motivo] durante [plazo].

También podés reclamar ante [autoridad de control: por ejemplo, la Agencia de Protección de Datos Personales en Chile o la autoridad de tu país en la UE].

### 7. Seguridad

Contraseñas y secretos cifrados de extremo a extremo, contraseña maestra que no sale de tu dispositivo, conexión cifrada (HTTPS), [segundo factor obligatorio / opcional], registro de auditoría. Ningún sistema es infalible: si detectamos un incidente que afecte tus datos, te avisaremos según lo que exija la ley.

### 8. Cambios

Si cambiamos esta política, lo avisaremos [en el servicio / por correo] antes de que rija.
