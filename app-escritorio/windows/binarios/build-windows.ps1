# Autor: Athan Espinoza
# Script de compilación y empaquetado autónomo para Windows
#
# Uso:
#   .\build-windows.ps1                          .exe + ZIP portable
#   .\build-windows.ps1 -Msi                     instalador MSI; la versión sube sola (0.1.0 -> 0.1.1 -> ...)
#   .\build-windows.ps1 -Msi -MantenerVersion    regenera el MSI sin cambiar la versión
#   .\build-windows.ps1 -Msi -Version 0.2.0      fija una versión explícita (para cambiar minor o major)
# Otras opciones: -SkipFrontend, -SkipExtension.
#
# Si PowerShell bloquea los scripts ("la ejecución de scripts está deshabilitada"):
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\build-windows.ps1 -Msi

param(
    [switch]$SkipFrontend = $false,
    # Punto 9: la extensión de navegador viaja embebida en el .exe. Omitirlo
    # reutiliza lo que ya haya en src-tauri\extension-bundle\ (o compila sin extensión).
    [switch]$SkipExtension = $false,
    # Genera el instalador MSI (sin firmar) en lugar del .exe suelto + zip. Ver
    # `src-tauri\tauri.msi.conf.json` y `src-tauri\installer\limpieza.wxs`.
    [switch]$Msi = $false,
    # Con -Msi la versión sube sola (el número de parche) y queda escrita en
    # `src-tauri\tauri.conf.json`, que es de donde la toman el instalador y la propia
    # app. -MantenerVersion no la toca; -Version fija una explícita (X.Y.Z).
    [switch]$MantenerVersion = $false,
    [string]$Version = ""
)

$ErrorActionPreference = "Stop"

if (($MantenerVersion -or $Version) -and -not $Msi) { throw "-MantenerVersion y -Version sólo se usan junto con -Msi." }
if ($MantenerVersion -and $Version) { throw "-MantenerVersion y -Version no se pueden usar a la vez." }
if ($Version -and $Version -notmatch '^\d+\.\d+\.\d+$') { throw "-Version debe tener el formato X.Y.Z (por ejemplo 0.2.0)." }

$Inicio = Get-Date
$DirScript = Split-Path -Parent $MyInvocation.MyCommand.Path
$DirRaiz = (Resolve-Path "$DirScript\..\..\..").Path
$DirFrontend = Join-Path $DirRaiz "frontend"
$DirTauri = Join-Path $DirRaiz "app-escritorio\src-tauri"
$DirDestino = $DirScript
$ConfTauri = Join-Path $DirTauri "tauri.conf.json"
$ArchivoTiempos = Join-Path $DirScript ".tiempos-build.json"
$Titulo = if ($Msi) { "Ellkan - instalador MSI" } else { "Ellkan - ejecutable y ZIP portable" }

Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "  Compilando Ellkan Desktop para Windows (Release)      " -ForegroundColor Cyan
Write-Host "=======================================================" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# Progreso. El porcentaje se reparte según lo que tardó cada paso la última vez
# (se guarda en .tiempos-build.json, que Git ignora); la primera vez usa
# estimaciones. Dentro de un paso largo (compilar) avanza con el tiempo, sin
# pasar del 95 % del paso hasta que termina de verdad.
# ---------------------------------------------------------------------------
$Tiempos = @{}
if (Test-Path $ArchivoTiempos) {
    try {
        $Guardado = Get-Content $ArchivoTiempos -Raw | ConvertFrom-Json
        foreach ($Campo in $Guardado.PSObject.Properties) { $Tiempos[$Campo.Name] = [double]$Campo.Value }
    } catch {
        $Tiempos = @{}
    }
}

$Plan = New-Object System.Collections.ArrayList
$script:TotalEstimado = 1.0
$script:HechoEstimado = 0.0
$script:Paso = $null
$script:InicioPaso = Get-Date
$script:UltimoAviso = Get-Date

function Agregar-Paso([string]$Nombre, [double]$SegundosPorDefecto) {
    $Estimado = $SegundosPorDefecto
    if ($Tiempos.ContainsKey($Nombre) -and $Tiempos[$Nombre] -ge 1) { $Estimado = $Tiempos[$Nombre] }
    [void]$Plan.Add([pscustomobject]@{ Nombre = $Nombre; Estimado = $Estimado; Real = 0.0 })
}

function Formato-Duracion([double]$Segundos) {
    $S = [int][math]::Round([math]::Max(0, $Segundos))
    if ($S -ge 60) { return ('{0}m {1:00}s' -f [int][math]::Floor($S / 60), ($S % 60)) }
    return ('{0}s' -f $S)
}

function Calcular-Avance {
    $Actual = 0.0
    if ($script:Paso) {
        $Transcurrido = ((Get-Date) - $script:InicioPaso).TotalSeconds
        $Actual = $script:Paso.Estimado * [math]::Min(0.95, $Transcurrido / $script:Paso.Estimado)
    }
    $Hecho = $script:HechoEstimado + $Actual
    return [pscustomobject]@{
        Porcentaje = [int][math]::Floor(100 * $Hecho / $script:TotalEstimado + 0.0001)
        Restante   = [math]::Max(0, $script:TotalEstimado - $Hecho)
    }
}

function Mostrar-Avance([string]$Detalle) {
    $A = Calcular-Avance
    $Estado = '{0}% - {1} (quedan ~{2})' -f $A.Porcentaje, $Detalle, (Formato-Duracion $A.Restante)
    Write-Progress -Activity $Titulo -Status $Estado -PercentComplete ([math]::Min(100, $A.Porcentaje)) -SecondsRemaining ([int]$A.Restante)
}

function Iniciar-Paso([string]$Nombre) {
    $script:Paso = $Plan | Where-Object { $_.Nombre -eq $Nombre } | Select-Object -First 1
    if (-not $script:Paso) { throw "Paso desconocido: $Nombre" }
    $script:InicioPaso = Get-Date
    $script:UltimoAviso = Get-Date
    $A = Calcular-Avance
    Write-Host ('[{0,3}%] {1}...' -f $A.Porcentaje, $Nombre) -ForegroundColor Green
    Mostrar-Avance $Nombre
}

function Terminar-Paso {
    $Duracion = ((Get-Date) - $script:InicioPaso).TotalSeconds
    $Nombre = $script:Paso.Nombre
    $script:Paso.Real = $Duracion
    $script:HechoEstimado += $script:Paso.Estimado
    $script:Paso = $null
    $A = Calcular-Avance
    Write-Host ('[{0,3}%] {1}: listo ({2})' -f $A.Porcentaje, $Nombre, (Formato-Duracion $Duracion)) -ForegroundColor DarkGreen
    Mostrar-Avance $Nombre
}

# Ejecuta un programa mostrando su salida en vivo y, mientras corre, mantiene la
# barra de progreso avanzando y avisa cada 30 s cuánto lleva.
function Invocar-Nativo {
    param([string]$Archivo, [string[]]$Argumentos, [string]$Directorio, [string]$MensajeError)
    $Texto = ($Argumentos | ForEach-Object {
        if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
    }) -join ' '
    $Proceso = Start-Process -FilePath $Archivo -ArgumentList $Texto -WorkingDirectory $Directorio -NoNewWindow -PassThru
    $null = $Proceso.Handle
    while (-not $Proceso.HasExited) {
        Start-Sleep -Milliseconds 500
        $Nombre = $script:Paso.Nombre
        $Lleva = Formato-Duracion (((Get-Date) - $script:InicioPaso).TotalSeconds)
        Mostrar-Avance "$Nombre, lleva $Lleva"
        if (((Get-Date) - $script:UltimoAviso).TotalSeconds -ge 30) {
            $script:UltimoAviso = Get-Date
            $A = Calcular-Avance
            Write-Host ('[{0,3}%] {1}: sigue en marcha ({2}, quedan ~{3})' -f $A.Porcentaje, $Nombre, $Lleva, (Formato-Duracion $A.Restante)) -ForegroundColor DarkGray
        }
    }
    $Proceso.WaitForExit()
    if ($Proceso.ExitCode -ne 0) { throw "$MensajeError (código de salida $($Proceso.ExitCode))." }
}

# ---------------------------------------------------------------------------
# Versión (sólo con -Msi): la fuente única es "version" de tauri.conf.json.
# ---------------------------------------------------------------------------
$ConfOriginal = $null
$VersionAnterior = $null
$VersionNueva = $null

if ($Msi) {
    $ConfOriginal = [System.IO.File]::ReadAllText($ConfTauri)
    $Coincide = [regex]::Match($ConfOriginal, '"version"\s*:\s*"(\d+)\.(\d+)\.(\d+)"')
    if (-not $Coincide.Success) { throw "No se encontró un campo `"version`" con formato X.Y.Z en $ConfTauri." }
    $Mayor = [int]$Coincide.Groups[1].Value
    $Menor = [int]$Coincide.Groups[2].Value
    $Parche = [int]$Coincide.Groups[3].Value
    $VersionAnterior = "$Mayor.$Menor.$Parche"

    if ($Version) {
        $VersionNueva = $Version
    } elseif ($MantenerVersion) {
        $VersionNueva = $VersionAnterior
    } else {
        $VersionNueva = "$Mayor.$Menor.$($Parche + 1)"
    }

    # Límites de Windows Installer: major y minor hasta 255, parche hasta 65535.
    $Partes = $VersionNueva.Split('.') | ForEach-Object { [int]$_ }
    if ($Partes[0] -gt 255 -or $Partes[1] -gt 255 -or $Partes[2] -gt 65535) {
        throw "La versión $VersionNueva no es válida para un MSI (máximos: 255.255.65535)."
    }
}

# ---------------------------------------------------------------------------
# Plan de pasos (con su duración estimada en segundos la primera vez).
# ---------------------------------------------------------------------------
Agregar-Paso "Cerrar Ellkan si está abierto" 2
if ($Msi) {
    if (-not $SkipExtension) { Agregar-Paso "Preparar la extensión de navegador" 20 }
    Agregar-Paso "Compilar la app y empaquetar el MSI" 420
    Agregar-Paso "Traducir los accesos directos del MSI" 6
    Agregar-Paso "Copiar el MSI" 2
} else {
    if (-not $SkipFrontend) { Agregar-Paso "Compilar el frontend" 45 }
    if (-not $SkipExtension) { Agregar-Paso "Preparar la extensión de navegador" 20 }
    Agregar-Paso "Compilar el ejecutable (release)" 240
    Agregar-Paso "Copiar los binarios" 3
    Agregar-Paso "Generar el ZIP portable" 8
}
$script:TotalEstimado = ($Plan | Measure-Object -Property Estimado -Sum).Sum

$Exito = $false
try {
    if ($Msi) {
        if ($VersionNueva -ne $VersionAnterior) {
            $ConfNueva = $ConfOriginal.Substring(0, $Coincide.Index) + '"version": "' + $VersionNueva + '"' + $ConfOriginal.Substring($Coincide.Index + $Coincide.Length)
            [System.IO.File]::WriteAllText($ConfTauri, $ConfNueva, (New-Object System.Text.UTF8Encoding($false)))
            Write-Host "Versión: $VersionAnterior -> $VersionNueva (queda en src-tauri\tauri.conf.json)" -ForegroundColor Yellow
        } else {
            Write-Host "Versión: $VersionNueva (sin cambios)" -ForegroundColor Yellow
        }
    }

    # Cerrar procesos activos para evitar errores de archivo bloqueado
    Iniciar-Paso "Cerrar Ellkan si está abierto"
    $Procesos = Get-Process ellkan-desktop -ErrorAction SilentlyContinue
    if ($Procesos) {
        Write-Host "      Cerrando ellkan-desktop..." -ForegroundColor Yellow
        $Procesos | Stop-Process -Force
        Start-Sleep -Seconds 1
    }
    Terminar-Paso

    $env:SQLX_OFFLINE = "true"

    if ($Msi) {
        # MSI con desinstalador (Configuración > Aplicaciones y acceso directo
        # "Desinstalar Ellkan" en el menú Inicio). Tauri arma el MSI con WiX (la
        # primera vez descarga WiX 3, hace falta conexión) y, antes de compilar,
        # construye el frontend (`beforeBuildCommand` de tauri.conf.json).
        if (-not $SkipExtension) {
            Iniciar-Paso "Preparar la extensión de navegador"
            Invocar-Nativo "node" @((Join-Path $DirRaiz "app-escritorio\scripts\preparar-extension.mjs")) $DirRaiz "Error: no se pudo preparar la extensión de navegador"
            Terminar-Paso
        }

        Iniciar-Paso "Compilar la app y empaquetar el MSI"
        $TauriCli = Join-Path $DirFrontend "node_modules\@tauri-apps\cli\tauri.js"
        Invocar-Nativo "node" @($TauriCli, "build", "--config", "tauri.msi.conf.json", "--bundles", "msi") $DirTauri "Error: falló el empaquetado del MSI"
        Terminar-Paso

        $Paquete = Get-ChildItem (Join-Path $DirRaiz "target\release\bundle\msi") -Filter "*_$($VersionNueva)_*.msi" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if (-not $Paquete) { throw "Error: no se encontró el MSI de la versión $VersionNueva." }

        # La plantilla de Tauri trae los accesos directos en inglés ("Uninstall
        # Ellkan", "Runs Ellkan"): se traducen dentro del MSI ya armado. El nombre
        # del acceso directo de desinstalación es "<nombre corto>|<nombre largo>",
        # y el corto lo genera Tauri, así que se conserva.
        Iniciar-Paso "Traducir los accesos directos del MSI"
        $Instalador = New-Object -ComObject WindowsInstaller.Installer
        $Base = $Instalador.OpenDatabase($Paquete.FullName, 1)
        $Textos = @(
            @{ Atajo = 'UninstallShortcut';           Nombre = 'Desinstalar Ellkan'; Descripcion = 'Quita Ellkan de este equipo (tus datos se conservan salvo que pidas borrarlos)' },
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
        Terminar-Paso

        Iniciar-Paso "Copiar el MSI"
        Copy-Item $Paquete.FullName -Destination $DirDestino -Force
        Terminar-Paso
        $Resultado = Join-Path $DirDestino $Paquete.Name
    } else {
        if (-not $SkipFrontend) {
            Iniciar-Paso "Compilar el frontend"
            Invocar-Nativo "cmd.exe" @("/c", "pnpm build") $DirFrontend "Error: falló la compilación del frontend"
            Terminar-Paso
        } else {
            Write-Host "      Omitiendo la compilación del frontend (-SkipFrontend)." -ForegroundColor Yellow
        }

        # Verificar que frontend/build/index.html exista
        $IndexHtml = Join-Path $DirFrontend "build\index.html"
        if (-not (Test-Path $IndexHtml)) {
            throw "Error crítico: No se encontró '$IndexHtml'. Debe compilarse el frontend antes de empaquetar."
        }

        # Preparar la extensión de navegador para embeberla en el ejecutable
        if (-not $SkipExtension) {
            Iniciar-Paso "Preparar la extensión de navegador"
            Invocar-Nativo "node" @((Join-Path $DirRaiz "app-escritorio\scripts\preparar-extension.mjs")) $DirRaiz "Error: no se pudo preparar la extensión de navegador (use -SkipExtension para compilar sin ella)"
            Terminar-Paso
        } else {
            Write-Host "      Omitiendo la extensión de navegador (-SkipExtension)." -ForegroundColor Yellow
        }

        Iniciar-Paso "Compilar el ejecutable (release)"
        Invocar-Nativo "cargo" @("build", "--release") $DirTauri "Error: falló la compilación del ejecutable"
        Terminar-Paso

        Iniciar-Paso "Copiar los binarios"
        $ExePrincipal = Join-Path $DirRaiz "target\release\ellkan-desktop.exe"
        $ExeAskpass = Join-Path $DirRaiz "target\release\ellkan_askpass.exe"
        if (-not (Test-Path $ExePrincipal)) {
            throw "Error: No se encontró el ejecutable principal '$ExePrincipal'."
        }
        Copy-Item $ExePrincipal -Destination $DirDestino -Force
        if (Test-Path $ExeAskpass) {
            Copy-Item $ExeAskpass -Destination $DirDestino -Force
        }
        Terminar-Paso

        Iniciar-Paso "Generar el ZIP portable"
        $ZipDestino = Join-Path $DirDestino "ellkan-desktop-portable.zip"
        $ArchivosZip = @(
            (Join-Path $DirDestino "ellkan-desktop.exe"),
            (Join-Path $DirDestino "ellkan_askpass.exe")
        ) | Where-Object { Test-Path $_ }
        Compress-Archive -Path $ArchivosZip -DestinationPath $ZipDestino -Force
        Terminar-Paso

        # Verificación final de integridad de tamaño
        $ItemExe = Get-Item (Join-Path $DirDestino "ellkan-desktop.exe")
        if ($ItemExe.Length -lt 5000000) {
            Write-Warning "Advertencia: El tamaño del ejecutable ($($ItemExe.Length) bytes) es menor al esperado. Verifique que los assets web hayan sido embebidos."
        } else {
            Write-Host "Verificación OK: Ejecutable con frontend embebido ($([math]::Round($ItemExe.Length / 1MB, 2)) MB)." -ForegroundColor Green
        }
        $Resultado = $null
    }

    $Exito = $true
} catch {
    # Un empaquetado fallido no debe gastar un número de versión.
    if ($Msi -and $ConfOriginal -and $VersionNueva -ne $VersionAnterior) {
        [System.IO.File]::WriteAllText($ConfTauri, $ConfOriginal, (New-Object System.Text.UTF8Encoding($false)))
        Write-Host "Se restauró la versión $VersionAnterior en tauri.conf.json (el empaquetado falló)." -ForegroundColor Yellow
    }
    throw
} finally {
    Write-Progress -Activity $Titulo -Completed
}

# Guardar lo que tardó cada paso para que el próximo porcentaje sea más fiel.
if ($Exito) {
    foreach ($P in $Plan) { if ($P.Real -gt 0) { $Tiempos[$P.Nombre] = [math]::Round($P.Real, 1) } }
    try { ($Tiempos | ConvertTo-Json) | Set-Content -Path $ArchivoTiempos -Encoding UTF8 } catch { }
}

$Total = Formato-Duracion (((Get-Date) - $Inicio).TotalSeconds)
Write-Host "=======================================================" -ForegroundColor Cyan
Write-Host "[100%] Compilación finalizada con éxito en $Total" -ForegroundColor Cyan
if ($Msi) {
    Write-Host "  Versión ${VersionNueva}: $Resultado" -ForegroundColor Cyan
    if ($VersionNueva -ne $VersionAnterior) {
        Write-Host "  La versión nueva quedó en src-tauri\tauri.conf.json: inclúyela en tu próximo commit." -ForegroundColor Cyan
    }
} else {
    Write-Host "  Carpeta: $DirDestino" -ForegroundColor Cyan
}
Write-Host "=======================================================" -ForegroundColor Cyan
if ($Msi) {
    Get-Item $Resultado | Select-Object Name, Length, LastWriteTime
} else {
    Get-ChildItem -Path $DirDestino | Select-Object Name, Length, LastWriteTime
}
