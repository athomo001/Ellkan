# Binarios y Paquetes de Distribución — Linux

Este directorio aloja los paquetes compilados para distribuciones Linux:

- **DEB**: Debian, Ubuntu, Linux Mint, Pop!_OS, Elementary OS, etc.
- **RPM**: Fedora, Red Hat Enterprise Linux, CentOS Stream, openSUSE, etc.
- **AppImage**: Formato autónomo y portable para cualquier distribución Linux con FUSE o WebKitGTK.

## Generación automatizada
Para generar los instaladores nativos en un entorno o contenedor Linux, ejecutar:
```bash
./build-linux.sh                          # .deb + .rpm + .AppImage
./build-linux.sh --bundles appimage       # sólo el AppImage
```

El script elige solo entre dos modos (se puede forzar con `--modo linux` o `--modo wsl`):

- **linux** — Linux nativo, o el repo clonado dentro del disco de Linux. Copia con `rsync`.
- **wsl** — WSL con el repo en un disco de Windows (`/mnt/c`, `/mnt/e`…). Primero copia con `robocopy.exe` desde Windows a `%TEMP%\ellkan-wsl-build` y de ahí a Linux. Hace falta porque algunos archivos tienen permisos de Windows que WSL no puede leer (`rsync: … Permission denied (13)`, aunque en Windows se abran bien); la copia hecha por Windows los deja con permisos normales sin tocar los originales.

En los dos modos nunca se copian `secrets/`, `.env` ni `investigacion/`.

Los artefactos resultantes se almacenan en este mismo directorio y se distribuyen en GitHub Releases.
