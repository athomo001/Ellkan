# Binarios y Paquetes de Distribución — Windows

Este directorio aloja los ejecutables y paquetes para sistemas operativos Windows (x64):

- `ellkan-desktop.exe`: Ejecutable autónomo optimizado con LTO (WebView2 runtime).
- `ellkan_askpass.exe`: Helper de inyección segura de contraseñas para terminales SSH asistidas (F-49).
- `ellkan-desktop-portable.zip`: Paquete zip portable listo para usar sin requerir privilegios de administrador.
- `Ellkan_<versión>_x64_es-ES.msi`: instalador (sin firmar) generado con `.\build-windows.ps1 -Msi` (WiX 3 vía Tauri; la primera vez descarga WiX, hace falta internet). Se desinstala desde Configuración → Aplicaciones o con «Desinstalar Ellkan» del menú Inicio; al desinstalar pregunta si borrar también los datos del usuario (por defecto los conserva).

## Compilación y empaquetado automatizado
Para compilar y empaquetar de forma determinista con el frontend estático incrustado (evitando cualquier dependencia de servidor de desarrollo en tiempo de ejecución):
```powershell
# Desde esta misma carpeta:
.\build-windows.ps1          # .exe + zip portable
.\build-windows.ps1 -Msi     # instalador MSI; la versión sube sola (0.1.0 -> 0.1.1 -> ...)
.\build-windows.ps1 -Msi -MantenerVersion   # sin subir la versión
.\build-windows.ps1 -Msi -Version 0.2.0     # fija una versión

# Si PowerShell dice que la ejecución de scripts está deshabilitada:
powershell -NoProfile -ExecutionPolicy Bypass -File .\build-windows.ps1 -Msi

# O desde la carpeta frontend:
pnpm build:desktop
```
Mientras compila muestra el porcentaje de avance y el tiempo restante estimado. Con `-Msi` reescribe `version` en `src-tauri\tauri.conf.json` (de ahí salen el nombre del `.msi`, el instalador y la versión que muestra la app): inclúyelo en el commit.

El script cierra automáticamente procesos activos en ejecución para evitar bloqueos de archivos, compila el frontend web, genera los ejecutables release de Rust con LTO, valida el tamaño final (>8 MB) y actualiza el zip portable de distribución.
