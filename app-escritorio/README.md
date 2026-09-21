# Ellkan — Aplicación de Escritorio (Desktop)
# Autor: Athan Espinoza

**Guía de uso, seguridad y compilación: [GUIA.md](GUIA.md).**

Estructura de la aplicación de escritorio aislada del código de la aplicación web:

```
app-escritorio/
├── backend-desktop/        # Backend local in-process (SQLite + Axum) [Compartido: Windows y Linux]
├── src-tauri/              # Contenedor gráfico nativo (Tauri v2) [Compartido: Windows y Linux]
├── windows/
│   └── binarios/           # Salida exclusiva de binarios e instaladores de Windows (.exe, .msi)
└── linuxOS/
    └── binarios/           # Salida exclusiva de paquetes y binarios de Linux (.AppImage, .deb)
```

## Propósito de cada módulo

### 1. `backend-desktop/` (Común: Windows y Linux)
- Es el backend Axum local con base de datos embebida SQLite.
- Permite que la aplicación de escritorio funcione de forma 100% autónoma sin requerir Docker ni PostgreSQL.
- Al estar programado en Rust estándar, **es el mismo para Windows y Linux**.

### 2. `src-tauri/` (Común: Windows y Linux)
- Cascarón de escritorio desarrollado en Tauri v2.
- Utiliza WebView2 en Windows y WebKitGTK en Linux para renderizar la interfaz SvelteKit en una ventana nativa.
- La resolución del directorio de datos está condicionada por sistema operativo (`src/lib.rs`):
  - **Windows**: `%APPDATA%\Ellkan`
  - **Linux**: `$XDG_DATA_HOME/ellkan` (o fallback a `~/.local/share/ellkan`)

### 3. `windows/binarios/` (Específico Windows)
- Carpeta designada para almacenar los ejecutables compilados finales (`.exe`) e instaladores (`.msi`) de Windows.

### 4. `linuxOS/binarios/` (Específico Linux)
- Carpeta designada para almacenar los paquetes finales distribuidos (`.AppImage`, `.deb`, etc.) de Linux.
