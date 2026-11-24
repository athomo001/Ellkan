# Autor: Athan Espinoza
#
# Instalador del servidor Ellkan para Windows (Docker). Hace todo lo que el
# README pedía a mano: crea el .env, genera los secretos, levanta los
# contenedores, espera a que el servidor responda y abre el navegador en la
# pantalla para crear la cuenta de administrador, con el token de instalación
# ya puesto.
#
# Uso (desde la carpeta del repo):
#   powershell -ExecutionPolicy Bypass -File .\instalar.ps1
#
# Se puede correr las veces que haga falta: no regenera secretos que ya
# existen ni toca una base que ya tiene datos.
#
# Compatible con Windows PowerShell 5.1 (sin `??`, ternarios ni `&&`).
# El archivo va en UTF-8 con BOM: sin BOM, PowerShell 5.1 lo lee como ANSI y
# los acentos de los mensajes salen rotos.

$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

# Docker escribe UTF-8; con la consola en la página 850 (Windows en español)
# los acentos de su salida llegarían mal. Se restaura al salir.
$codificacionOriginal = [Console]::OutputEncoding
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false

function Escribir-Paso([string]$texto) { Write-Host ""; Write-Host "==> $texto" -ForegroundColor Cyan }
function Escribir-Ok([string]$texto) { Write-Host "    $texto" -ForegroundColor Green }
function Escribir-Info([string]$texto) { Write-Host "    $texto" }
function Detener-Instalacion([string]$texto) {
    Write-Host ""
    Write-Host "No se pudo terminar la instalación:" -ForegroundColor Red
    Write-Host $texto -ForegroundColor Red
    [Console]::OutputEncoding = $codificacionOriginal
    exit 1
}

# Corre docker con los argumentos dados y devuelve su salida (stdout+stderr)
# como texto, sin cortar el script si el comando falla: quien llama mira
# $LASTEXITCODE. `2>&1` con $ErrorActionPreference = 'Stop' convertiría
# cualquier línea de stderr en una excepción en PowerShell 5.1.
function Invocar-Docker([string[]]$argumentos) {
    $anterior = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $salida = & docker @argumentos 2>&1 | ForEach-Object { "$_" } }
    finally { $ErrorActionPreference = $anterior }
    return ($salida -join "`n")
}

function Escribir-Secreto([string]$ruta, [string]$valor) {
    # Sin salto de línea y en ASCII: un `\r\n` o un BOM quedarían pegados a la
    # contraseña dentro del contenedor Linux.
    [System.IO.File]::WriteAllText((Join-Path $PSScriptRoot $ruta), $valor, (New-Object System.Text.ASCIIEncoding))
}

function Leer-Secreto([string]$ruta) {
    $completa = Join-Path $PSScriptRoot $ruta
    if (-not (Test-Path -LiteralPath $completa)) { return '' }
    return ([System.IO.File]::ReadAllText($completa)).Trim()
}

function Bytes-Aleatorios([int]$cantidad) {
    $bytes = New-Object byte[] $cantidad
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return ,$bytes
}

# --- 1. Docker ----------------------------------------------------------------
Escribir-Paso "Revisando Docker"
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Detener-Instalacion ("Docker no está instalado. Instalalo con:`n" +
        "    winget install --id Docker.DockerDesktop -e`n" +
        "Después abrí Docker Desktop, esperá a que diga que el motor está corriendo y volvé a correr este instalador.")
}

$null = Invocar-Docker @('info')
if ($LASTEXITCODE -ne 0) {
    $dockerDesktop = Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'
    if (Test-Path -LiteralPath $dockerDesktop) {
        Escribir-Info "Docker Desktop está cerrado: lo abro y espero a que arranque (puede tardar un minuto)..."
        Start-Process -FilePath $dockerDesktop
        $limite = (Get-Date).AddSeconds(180)
        do {
            Start-Sleep -Seconds 3
            $null = Invocar-Docker @('info')
        } while ($LASTEXITCODE -ne 0 -and (Get-Date) -lt $limite)
    }
    if ($LASTEXITCODE -ne 0) {
        Detener-Instalacion "Docker no responde. Abrí Docker Desktop, esperá a que diga que el motor está corriendo y volvé a correr este instalador."
    }
}

$null = Invocar-Docker @('compose', 'version')
if ($LASTEXITCODE -ne 0) {
    Detener-Instalacion "Falta Docker Compose v2 (el comando 'docker compose'). Actualizá Docker Desktop y volvé a correr este instalador."
}
Escribir-Ok "Docker listo."

# --- 2. Configuración (.env) --------------------------------------------------
Escribir-Paso "Configuración (.env)"
if (-not (Test-Path -LiteralPath '.env')) {
    Copy-Item -LiteralPath '.env.example' -Destination '.env'
    Escribir-Ok "Creé .env a partir de .env.example (valores por defecto)."
} else {
    Escribir-Ok "Uso el .env que ya existe."
}

# Se lee el .env acá mismo: nadie tiene que "cargarlo" en la terminal.
$config = @{}
foreach ($linea in [System.IO.File]::ReadAllLines((Join-Path $PSScriptRoot '.env'))) {
    if ($linea -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$') {
        $config[$Matches[1]] = $Matches[2].Trim('"', "'")
    }
}
function Valor-Config([string]$clave, [string]$porDefecto) {
    if ($config.ContainsKey($clave) -and $config[$clave]) { return $config[$clave] }
    return $porDefecto
}
$usuarioBase = Valor-Config 'POSTGRES_USER' 'ellkan'
$nombreBase = Valor-Config 'POSTGRES_DB' 'ellkan'
$puerto = Valor-Config 'ELLKAN_PORT' '8080'
$url = "http://localhost:$puerto"

# --- 3. Secretos --------------------------------------------------------------
Escribir-Paso "Secretos (carpeta secrets\)"
New-Item -ItemType Directory -Force -Path (Join-Path $PSScriptRoot 'secrets') | Out-Null

# ¿Ya hay una base creada? Si la hay, sus secretos no se pueden regenerar: la
# base guarda la contraseña en su volumen y la clave de secretos protege
# datos ya cifrados.
$proyecto = ''
$configJson = Invocar-Docker @('compose', 'config', '--format', 'json')
if ($LASTEXITCODE -eq 0) { $proyecto = ($configJson | ConvertFrom-Json).name }
if (-not $proyecto) { Detener-Instalacion "No pude leer docker-compose.yml:`n$configJson" }
$volumenes = Invocar-Docker @('volume', 'ls', '-q', '--filter', "label=com.docker.compose.project=$proyecto", '--filter', 'label=com.docker.compose.volume=postgres_data')
$baseExiste = [bool]($volumenes.Trim())

$reinstalar = "Si esta instalación no tiene datos que te importen, borrala y empezá de cero con:`n" +
    "    docker compose down -v`n" +
    "y volvé a correr este instalador."

$contrasena = Leer-Secreto 'secrets/postgres_password.txt'
if (-not $contrasena) {
    if ($baseExiste) { Detener-Instalacion ("Falta secrets\postgres_password.txt, pero la base de datos ya existe y necesita la contraseña con la que se creó.`n" + $reinstalar) }
    $contrasena = -join ((Bytes-Aleatorios 24) | ForEach-Object { $_.ToString('x2') })
    Escribir-Secreto 'secrets/postgres_password.txt' $contrasena
    Escribir-Ok "Generé la contraseña de la base de datos."
} else {
    Escribir-Ok "La contraseña de la base de datos ya existe: la conservo."
}

$claveSecretos = Leer-Secreto 'secrets/ellkan_secrets_key.txt'
if (-not $claveSecretos) {
    if ($baseExiste) { Detener-Instalacion ("Falta secrets\ellkan_secrets_key.txt, pero la base de datos ya existe y tiene datos cifrados con esa clave.`n" + $reinstalar) }
    Escribir-Secreto 'secrets/ellkan_secrets_key.txt' ([Convert]::ToBase64String((Bytes-Aleatorios 32)))
    Escribir-Ok "Generé la clave de secretos del servidor."
} else {
    Escribir-Ok "La clave de secretos ya existe: la conservo."
}

# La URL se arma siempre desde el .env y la contraseña: así nunca queda
# desincronizada (antes, sin cargar el .env, salía sin usuario ni base).
$urlBase = "postgres://${usuarioBase}:${contrasena}@ellkan-db:5432/${nombreBase}"
if ((Leer-Secreto 'secrets/database_url.txt') -ne $urlBase) {
    Escribir-Secreto 'secrets/database_url.txt' $urlBase
    Escribir-Ok "Escribí la conexión a la base (usuario '$usuarioBase', base '$nombreBase')."
} else {
    Escribir-Ok "La conexión a la base ya está bien."
}

# --- 4. Levantar ----------------------------------------------------------------
Escribir-Paso "Levantando Ellkan (la primera vez descarga las imágenes)"
$anterior = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try { & docker compose up -d } finally { $ErrorActionPreference = $anterior }
if ($LASTEXITCODE -ne 0) {
    Detener-Instalacion ("'docker compose up' falló (el error está arriba).`n" +
        "Si dice 'bind source path does not exist' aunque el archivo existe, Docker Desktop no está viendo el disco: reinicialo (o 'wsl --shutdown') y volvé a correr este instalador.`n" +
        "Si dice que el puerto está en uso, cambiá ELLKAN_PORT o POSTGRES_PORT en .env.")
}

# --- 5. Esperar a que responda ----------------------------------------------------
Escribir-Paso "Esperando a que el servidor responda en $url"
$estado = $null
$limite = (Get-Date).AddSeconds(180)
while ((Get-Date) -lt $limite) {
    try {
        $estado = Invoke-RestMethod -Uri "$url/auth/setup-status" -UseBasicParsing -TimeoutSec 5
        break
    } catch {
        # 404: imagen anterior a la 0.1.71, sin /auth/setup-status, pero el servidor está arriba.
        if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 404) { $estado = 'sin-setup-status'; break }
    }
    $reinicios = Invocar-Docker @('inspect', '-f', '{{.RestartCount}}', 'ellkan')
    if ($LASTEXITCODE -eq 0 -and $reinicios.Trim() -match '^\d+$' -and [int]$reinicios.Trim() -ge 3) {
        $ultimas = Invocar-Docker @('compose', 'logs', '--no-log-prefix', '--tail', '15', 'ellkan')
        Detener-Instalacion ("El servidor se reinicia una y otra vez. Últimas líneas de su log:`n$ultimas`n`n" +
            "Si dice 'password authentication failed', la base se creó con otros datos: " + $reinstalar)
    }
    Start-Sleep -Seconds 3
}
if (-not $estado) {
    $ultimas = Invocar-Docker @('compose', 'logs', '--no-log-prefix', '--tail', '15', 'ellkan')
    Detener-Instalacion "El servidor no respondió en 3 minutos. Últimas líneas de su log:`n$ultimas"
}
Escribir-Ok "El servidor responde."

# --- 6. Primera cuenta ----------------------------------------------------------
Escribir-Paso "Cuenta de administrador"
$abrir = $url
if ($estado -eq 'sin-setup-status') {
    Escribir-Info "Esta versión de Ellkan es anterior a la 0.1.71 y NO pide token de instalación:"
    Escribir-Info "creá tu cuenta ya, antes de dejar el servidor accesible desde la red."
    $abrir = "$url/register"
} elseif ($estado.setup_token_required) {
    $logs = Invocar-Docker @('compose', 'logs', '--no-log-prefix', 'ellkan')
    $coincidencias = [regex]::Matches($logs, 'token de instalaci\S*n: ([0-9a-f]{48})')
    if ($coincidencias.Count -gt 0) {
        # El último: el token cambia en cada arranque mientras no haya cuentas.
        $token = $coincidencias[$coincidencias.Count - 1].Groups[1].Value
        $abrir = "$url/register#setup=$token"
        Escribir-Info "Token de instalación: $token"
        Escribir-Info "(sirve para crear la primera cuenta, que queda como administradora; cambia si el servidor se reinicia antes)"
    } else {
        # Token propio configurado con ELLKAN_SETUP_TOKEN[_FILE]: no sale en el log.
        Escribir-Info "Esta instalación usa un token de instalación propio (ELLKAN_SETUP_TOKEN): pegalo en la pantalla de registro."
        $abrir = "$url/register"
    }
} else {
    Escribir-Info "Este servidor ya tiene cuentas: entrá con la tuya."
}

Write-Host ""
Write-Host "Listo. Ellkan está en $url" -ForegroundColor Green
Write-Host "Abrí este link para seguir: $abrir" -ForegroundColor Green
try { Start-Process $abrir } catch { }
[Console]::OutputEncoding = $codificacionOriginal
