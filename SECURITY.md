# Política de seguridad / Security policy

**Autor:** Athan Espinoza

## Cómo reportar una vulnerabilidad

Ellkan es un gestor de contraseñas: un fallo de seguridad puede exponer secretos de personas reales. Por eso, **no abras un issue público** para reportar una vulnerabilidad.

1. Usá el reporte privado de GitHub: pestaña **Security** del repositorio → **Report a vulnerability** (<https://github.com/athomo001/Ellkan/security/advisories/new>).
2. Contá qué versión probaste (servidor, app de escritorio o extensión, y su número de versión), los pasos para reproducirlo y el impacto que ves.
3. Si podés, no publiques detalles hasta que haya una versión corregida.

Qué podés esperar:

- Respuesta inicial dentro de **7 días**.
- Una evaluación de severidad y, si se confirma, un plan de corrección.
- Crédito en el CHANGELOG si lo querés.

Es un proyecto mantenido por una sola persona, sin programa de recompensas (bug bounty).

## Alcance

Dentro del alcance: el servidor (`backend/`), el núcleo criptográfico (`crates/ellkan-crypto`), el frontend web, la extensión de navegador, la app de escritorio y la CLI de este repositorio.

Fuera del alcance: instalaciones de terceros mal configuradas (por ejemplo, sin TLS), ataques que requieren que el equipo del usuario ya esté comprometido por malware, y denegación de servicio por volumen.

## Prueba de buena fe

Si investigás de buena fe, sin acceder a datos de otras personas, sin degradar servicios ajenos y reportando por el canal privado, no voy a iniciar acciones en tu contra por esa investigación. Probá sólo contra tu propia instalación.

## Versiones con soporte

Ellkan está en beta: sólo la última versión publicada recibe correcciones de seguridad.

---

## Reporting a vulnerability (English)

Please **do not open a public issue**. Use GitHub private vulnerability reporting: **Security** tab → **Report a vulnerability** (<https://github.com/athomo001/Ellkan/security/advisories/new>). Include the component and version, steps to reproduce, and the impact. Expect an initial reply within 7 days. Only the latest release receives security fixes. Test only against your own installation; good-faith research reported privately will not be pursued.
