# Autor: Athan Espinoza
#
# Genera las dos imágenes del asistente del instalador MSI (tauri.msi.conf.json:
# bannerPath y dialogImagePath). Se vuelve a correr sólo si cambia el logo o el
# texto de abajo; los .bmp resultantes se guardan junto a este script.
#
#   powershell -ExecutionPolicy Bypass -File .\generar-imagenes.ps1
#
# Medidas EXACTAS que exige WiX (si no, el instalador las deforma):
#   dialogo.bmp  493 x 312  bienvenida y pantalla final. La franja izquierda
#                (164 px) es la imagen; el resto queda blanco porque encima se
#                dibuja el texto del asistente, así que no se pone nada ahí.
#   banner.bmp   493 x 58   franja superior del resto de pantallas; el título de
#                cada pantalla se dibuja a la izquierda, el logo va a la derecha.

Add-Type -AssemblyName System.Drawing

$Aqui = Split-Path -Parent $MyInvocation.MyCommand.Path
$Logo = Join-Path $Aqui "..\..\..\assets\logo\ellkan-icon-mark.png"

# Colores de la marca (frontend/src/lib/styles/tokens.css).
$Fondo = [System.Drawing.ColorTranslator]::FromHtml("#102335")
$Dorado = [System.Drawing.ColorTranslator]::FromHtml("#E0B860")
$Blanco = [System.Drawing.ColorTranslator]::FromHtml("#F8F8F8")
$Gris = [System.Drawing.ColorTranslator]::FromHtml("#B4C3D2")

# Texto del panel. Se escribe con códigos de carácter para que el archivo sea
# ASCII y no dependa de la codificación con que lo lea PowerShell.
$ContrasenaS = "contrase" + [char]0x00F1 + "as"
$Titulo = "Ellkan"
$Subtitulo = "Gestor de $ContrasenaS"
$Resumen = "Tus $ContrasenaS quedan cifradas en este equipo: sin nube ni servidor, y solo t" + [char]0x00FA + " puedes abrirlas."

function Nuevo-Lienzo($ancho, $alto, $colorFondo) {
    $bmp = New-Object System.Drawing.Bitmap($ancho, $alto, [System.Drawing.Imaging.PixelFormat]::Format24bppRgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear($colorFondo)
    return @{ Bmp = $bmp; G = $g }
}

# Parte `texto` en líneas que quepan en `anchoMax` píxeles con la fuente dada.
function Partir-Lineas($g, $texto, $fuente, $anchoMax) {
    $lineas = @()
    $actual = ""
    foreach ($palabra in ($texto -split " ")) {
        $prueba = if ($actual) { "$actual $palabra" } else { $palabra }
        if ($g.MeasureString($prueba, $fuente).Width -gt $anchoMax -and $actual) {
            $lineas += $actual
            $actual = $palabra
        } else {
            $actual = $prueba
        }
    }
    if ($actual) { $lineas += $actual }
    return $lineas
}

function Texto-Centrado($g, $texto, $fuente, $pincel, $centroX, $y) {
    $medida = $g.MeasureString($texto, $fuente)
    $g.DrawString($texto, $fuente, $pincel, [single]($centroX - $medida.Width / 2), [single]$y)
}

$Escudo = [System.Drawing.Image]::FromFile((Resolve-Path $Logo).Path)
$Proporcion = $Escudo.Width / $Escudo.Height

# ---------------------------------------------------------------- dialogo.bmp
$L = Nuevo-Lienzo 493 312 ([System.Drawing.Color]::White)
$g = $L.G
$PanelAncho = 164
$g.FillRectangle((New-Object System.Drawing.SolidBrush($Fondo)), 0, 0, $PanelAncho, 312)

$CentroX = $PanelAncho / 2
$EscudoAlto = 92
$EscudoAncho = [int]($EscudoAlto * $Proporcion)
$g.DrawImage($Escudo, [int]($CentroX - $EscudoAncho / 2), 22, $EscudoAncho, $EscudoAlto)

$FuenteTitulo = New-Object System.Drawing.Font("Segoe UI Semibold", 20, [System.Drawing.FontStyle]::Regular, [System.Drawing.GraphicsUnit]::Pixel)
$FuenteSub = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Regular, [System.Drawing.GraphicsUnit]::Pixel)
$FuenteCuerpo = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Regular, [System.Drawing.GraphicsUnit]::Pixel)

Texto-Centrado $g $Titulo $FuenteTitulo (New-Object System.Drawing.SolidBrush($Dorado)) $CentroX 126
Texto-Centrado $g $Subtitulo $FuenteSub (New-Object System.Drawing.SolidBrush($Blanco)) $CentroX 156
$g.FillRectangle((New-Object System.Drawing.SolidBrush($Dorado)), [int]($CentroX - 18), 182, 36, 2)

$Pincel = New-Object System.Drawing.SolidBrush($Gris)
$Y = 196
foreach ($linea in (Partir-Lineas $g $Resumen $FuenteCuerpo 126)) {
    Texto-Centrado $g $linea $FuenteCuerpo $Pincel $CentroX $Y
    $Y += 16
}
$L.Bmp.Save((Join-Path $Aqui "dialogo.bmp"), [System.Drawing.Imaging.ImageFormat]::Bmp)
$g.Dispose(); $L.Bmp.Dispose()

# ------------------------------------------------------------------ banner.bmp
$L = Nuevo-Lienzo 493 58 ([System.Drawing.Color]::White)
$g = $L.G
# El logo tiene partes oscuras que se pierden sobre blanco: va sobre una placa
# de color de marca, con las esquinas redondeadas.
$AltoLogo = 40
$AnchoLogo = [int]($AltoLogo * $Proporcion)
$Margen = 6
$PlacaX = 493 - 12 - $AnchoLogo - 2 * $Margen
$PlacaAncho = $AnchoLogo + 2 * $Margen
$PlacaAlto = 52
$Radio = 8
$Placa = New-Object System.Drawing.Drawing2D.GraphicsPath
$Placa.AddArc($PlacaX, 3, $Radio * 2, $Radio * 2, 180, 90)
$Placa.AddArc($PlacaX + $PlacaAncho - $Radio * 2, 3, $Radio * 2, $Radio * 2, 270, 90)
$Placa.AddArc($PlacaX + $PlacaAncho - $Radio * 2, 3 + $PlacaAlto - $Radio * 2, $Radio * 2, $Radio * 2, 0, 90)
$Placa.AddArc($PlacaX, 3 + $PlacaAlto - $Radio * 2, $Radio * 2, $Radio * 2, 90, 90)
$Placa.CloseFigure()
$g.FillPath((New-Object System.Drawing.SolidBrush($Fondo)), $Placa)
$g.DrawImage($Escudo, $PlacaX + $Margen, 3 + [int](($PlacaAlto - $AltoLogo) / 2), $AnchoLogo, $AltoLogo)
$L.Bmp.Save((Join-Path $Aqui "banner.bmp"), [System.Drawing.Imaging.ImageFormat]::Bmp)
$g.Dispose(); $L.Bmp.Dispose()
$Escudo.Dispose()

Write-Host "Imagenes generadas en $Aqui"
