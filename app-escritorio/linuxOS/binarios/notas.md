# Binarios y Paquetes de Distribución — Linux

Este directorio aloja los paquetes compilados para distribuciones Linux:

- **DEB**: Debian, Ubuntu, Linux Mint, Pop!_OS, Elementary OS, etc.
- **RPM**: Fedora, Red Hat Enterprise Linux, CentOS Stream, openSUSE, etc.
- **AppImage**: Formato autónomo y portable para cualquier distribución Linux con FUSE o WebKitGTK.

## Generación automatizada
Para generar los instaladores nativos en un entorno o contenedor Linux, ejecutar:
```bash
./build-linux.sh
```
Los artefactos resultantes se almacenan en este mismo directorio y se distribuyen en GitHub Releases.
