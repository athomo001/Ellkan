<p align="center">
  <img src="assets/logo/ellkan-icon-mark-fondo-oscuro.png" alt="Ellkan" width="160">
</p>

<h1 align="center">Ellkan</h1>
<p align="center">Gestor de contraseñas zero-knowledge, self-hosted.</p>
<p align="center"><b>Español</b> (este archivo) · <a href="README.en.md">English</a></p>

**Ellkan** — del mapudungún *elkan*, "esconder, ocultar".

**ADVERTENCIA** : desarrollo en fase alpha

## Qué es Ellkan

Un gestor de contraseñas self-hosted con arquitectura zero-knowledge: el servidor nunca ve tus claves privadas ni tus secretos en claro. Backend en Rust (Axum), cifrado con primitivas modernas (X25519, Ed25519, XChaCha20-Poly1305, Argon2id), frontend web y extensión de navegador comparten el mismo núcleo criptográfico compilado a WebAssembly.

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

## Preguntas frecuentes

**¿El servidor puede ver mis contraseñas?**
No. Todo se cifra y se descifra en tu dispositivo, nunca en el servidor — es como dejarle a alguien una caja fuerte cerrada para guardar: puede guardarla, pero nunca tiene la llave para abrirla ni ver qué hay adentro.

**¿Qué pasa si alguien roba la base de datos del servidor?**
No consigue tus contraseñas — sólo consigue cajas fuertes cerradas. Sin tu contraseña maestra (que nunca se guarda en ningún lado, ni en el servidor), no hay forma de abrirlas.

**¿Cómo protegen mis claves en la memoria de la computadora (RAM) mientras las uso?**
La clave nunca queda "dando vueltas" guardada en la memoria, esperando a que alguien la agarre. Cada vez que hace falta usarla, se reconstruye al toque a partir de tu contraseña, se usa un instante, y se borra inmediatamente — como escribir algo en un papel, usarlo una vez, y romperlo al toque, en vez de dejarlo dando vueltas sobre el escritorio. Tu contraseña maestra se guarda sólo mientras tenés la sesión abierta y nunca toca el disco: si cerrás el navegador o la app, se pierde sola. Lo único que esto no puede evitar es que, si tu computadora ya tiene un virus espiándola, ese virus vea la clave justo en el instante en que la estás usando — ningún gestor de contraseñas puede protegerte de eso, porque ahí el atacante ya está adentro de tu máquina, no del sistema.

## Estado

En desarrollo activo, etapa temprana.

## Licencia

**AGPL-3.0** — ver [LICENSE](LICENSE) (texto oficial en inglés, el único legalmente vinculante) y [LICENSE.es.txt](LICENSE.es.txt) (traducción no oficial al español, sólo de referencia).
