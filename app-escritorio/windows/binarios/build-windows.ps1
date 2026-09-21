# Autor: Athan Espinoza
# Script de compilación y empaquetado autónomo para Windows
# Uso:  .\build-windows.ps1 [-Msi] [-SkipFrontend] [-SkipExtension]
# Si PowerShell bloquea los scripts ("la ejecución de scripts está deshabilitada"):
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\build-windows.ps1 -Msi

param(
    [switch]$SkipFrontend = $false,
    # Punto 9: la extensión de navegador viaja embebida en el .exe. Omitirlo
    # reutiliza lo que ya haya en src-tauri\extension-bundle\ (o compila sin extensión).
    [switch]$SkipExtension = $false,
    # Genera el instalador MSI (sin firmar) en lugar del .exe suelto + zip. Ver
    # `src-tauri\tauri.msi.conf.json` y `src-tauri\installer\limpieza.wxs`.
    [switch]$Msi = $false
)

$ErrorActionPreference = "Stop"

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  Compilando Ellkan Desktop para Windows (Release)      " -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan

# 1. Determinar directorios
$DirScript = Split-Path -Parent $MyInvocation.MyCommand.Path
$DirRaiz = (Resolve-Path "$DirScript\..\..\..").Path
$DirFrontend = Join-Path $DirRaiz "frontend"
$DirTauri = Join-Path $DirRaiz "app-escritorio\src-tauri"
$DirDestino = $DirScript

# 2. Cerrar procesos activos para evitar errores de archivo bloqueado
$procesos = Get-Process ellkan-desktop -ErrorAction SilentlyContinue
if ($procesos) {
    Write-Host "[0/4] Cerrando procesos previos de ellkan-desktop..." -ForegroundColor Yellow
    $procesos | Stop-Process -Force
    Start-Sleep -Seconds 1
}

# Modo instalador: MSI con desinstalador (Configuración > Aplicaciones y acceso
# directo "Desinstalar Ellkan" en el menú Inicio). Tauri arma el MSI con WiX
# (la primera vez descarga WiX 3, hace falta conexión).
if ($Msi) {
    if (-not $SkipExtension) {
        Write-Host "[MSI 1/2] Preparando la extensión de navegador..." -ForegroundColor Green
        node (Join-Path $DirRaiz "app-escritorio\scripts\preparar-extension.mjs")
        if ($LASTEXITCODE -ne 0) { throw "Error: no se pudo preparar la extensión de navegador." }
    }
    $env:SQLX_OFFLINE = "true"
    Write-Host "[MSI 2/2] Compilando la app y empaquetando el MSI (tarda varios minutos)..." -ForegroundColor Green
    Push-Location $DirTauri
    try {
        node (Join-Path $DirFrontend "node_modules\@tauri-apps\cli\tauri.js") build --config tauri.msi.conf.json --bundles msi
        if ($LASTEXITCODE -ne 0) { throw "Error: falló el empaquetado del MSI." }
    } finally {
        Pop-Location
    }

    $Paquete = Get-ChildItem (Join-Path $DirRaiz "target\release\bundle\msi\*.msi") | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $Paquete) { throw "Error: no se encontró el MSI generado." }

    # La plantilla de Tauri trae los accesos directos en inglés ("Uninstall
    # Ellkan", "Runs Ellkan"): se traducen dentro del MSI ya armado. El nombre
    # del acceso directo de desinstalación es "<nombre corto>|<nombre largo>",
    # y el corto lo genera Tauri, así que se conserva.
    $Instalador = New-Object -ComObject WindowsInstaller.Installer
    $Base = $Instalador.OpenDatabase($Paquete.FullName, 1)
    $Textos = @(
        @{ Atajo = 'UninstallShortcut';           Nombre = 'Desinstalar Ellkan'; Descripcion = 'Quita Ellkan de este equipo (tus datos se conservan)' },
        @{ Atajo = 'ApplicationStartMenuShortcut'; Nombre = $null;               Descripcion = 'Abre Ellkan' },
        @{ Atajo = 'ApplicationDesktopShortcut';   Nombre = $null;               Descripcion = 'Abre Ellkan' }
    )
    foreach ($T in $Textos) {
        $Vista = $Base.OpenView("SELECT Name, Description FROM Shortcut WHERE Shortcut='$($T.Atajo)'")
        $Vista.Execute()
        $Fila = $Vista.Fetch()
        if ($Fila) {
            if ($T.Nombre) { $Fila.StringData(1) = ((($Fila.StringData(1) -split '\|')[0]) + '|' + $T.Nombre) }
            $Fila.StringData(2) = $T.Descripcion
            $Vista.Modify(2, $Fila)
        }
        $Vista.Close()
        [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($Vista)
    }
    $Base.Commit()
    [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($Base)
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()

    Copy-Item $Paquete.FullName -Destination $DirDestino -Force
    Write-Host "MSI listo: $(Join-Path $DirDestino $Paquete.Name)" -ForegroundColor Cyan
    Get-Item (Join-Path $DirDestino $Paquete.Name) | Select-Object Name, Length, LastWriteTime
    return
}

# 3. Compilar frontend estático si no se omite explícitamente
if (-not $SkipFrontend) {
    Write-Host "[1/4] Compilando frontend estático de producción..." -ForegroundColor Green
    Push-Location $DirFrontend
    try {
        pnpm build
    } finally {
        Pop-Location
    }
} else {
    Write-Host "[1/4] Omitiendo compilación del frontend (-SkipFrontend activado)..." -ForegroundColor Yellow
}

# Verificar que frontend/build/index.html exista
$IndexHtml = Join-Path $DirFrontend "build\index.html"
if (-not (Test-Path $IndexHtml)) {
    throw "Error crítico: No se encontró '$IndexHtml'. Debe compilarse el frontend antes de empaquetar."
}

# 3b. Preparar la extensión de navegador para embeberla en el ejecutable
if (-not $SkipExtension) {
    Write-Host "[1b/4] Preparando la extensión de navegador (Chromium + Firefox)..." -ForegroundColor Green
    node (Join-Path $DirRaiz "app-escritorio\scripts\preparar-extension.mjs")
    if ($LASTEXITCODE -ne 0) {
        throw "Error: no se pudo preparar la extensión de navegador (ver el mensaje de arriba). Use -SkipExtension para compilar sin ella."
    }
} else {
    Write-Host "[1b/4] Omitiendo la extensión de navegador (-SkipExtension activado)..." -ForegroundColor Yellow
}

# 4. Compilar binario de escritorio en modo release con assets embebidos
Write-Host "[2/4] Compilando binario Rust con Tauri (release)..." -ForegroundColor Green
$env:SQLX_OFFLINE = "true"
Push-Location $DirTauri
try {
    cargo build --release
} finally {
    Pop-Location
}

# 5. Copiar binarios al directorio de distribución
Write-Host "[3/4] Copiando binarios a $DirDestino..." -ForegroundColor Green
$ExePrincipal = Join-Path $DirRaiz "target\release\ellkan-desktop.exe"
$ExeAskpass = Join-Path $DirRaiz "target\release\ellkan_askpass.exe"

if (-not (Test-Path $ExePrincipal)) {
    throw "Error: No se encontró el ejecutable principal '$ExePrincipal'."
}

Copy-Item $ExePrincipal -Destination $DirDestino -Force
if (Test-Path $ExeAskpass) {
    Copy-Item $ExeAskpass -Destination $DirDestino -Force
}

# 6. Generar archivo portable ZIP
Write-Host "[4/4] Generando archivo portable ZIP..." -ForegroundColor Green
$ZipDestino = Join-Path $DirDestino "ellkan-desktop-portable.zip"
$ArchivosZip = @(
    (Join-Path $DirDestino "ellkan-desktop.exe"),
    (Join-Path $DirDestino "ellkan_askpass.exe")
) | Where-Object { Test-Path $_ }

Compress-Archive -Path $ArchivosZip -DestinationPath $ZipDestino -Force

# 7. Verificación final de integridad de tamaño
$ItemExe = Get-Item (Join-Path $DirDestino "ellkan-desktop.exe")
if ($ItemExe.Length -lt 5000000) {
    Write-Warning "Advertencia: El tamaño del ejecutable ($($ItemExe.Length) bytes) es menor al esperado. Verifique que los assets web hayan sido embebidos."
} else {
    Write-Host "Verificación OK: Ejecutable con frontend embebido ($([math]::Round($ItemExe.Length / 1MB, 2)) MB)." -ForegroundColor Green
}

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  Compilación finalizada con éxito en: $DirDestino      " -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan
Get-ChildItem -Path $DirDestino | Select-Object Name, Length, LastWriteTime
