# Draws the Feverfew flower and writes assets\feverfew.ico.
Add-Type -AssemblyName System.Drawing

function New-FlowerPng([int]$size) {
    $bmp = New-Object System.Drawing.Bitmap $size, $size
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $g.Clear([System.Drawing.Color]::Transparent)
    $c = $size / 2.0
    $white = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 255, 255, 250))
    $edge = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(255, 120, 150, 95)), ([Math]::Max(1, $size / 48.0))
    $gold = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(255, 240, 180, 30))
    for ($i = 0; $i -lt 10; $i++) {
        $state = $g.Save()
        $g.TranslateTransform($c, $c)
        $g.RotateTransform($i * 36)
        $w = $size * 0.2; $h = $size * 0.42
        $g.FillEllipse($white, -$w / 2, -$size * 0.48, $w, $h)
        $g.DrawEllipse($edge, -$w / 2, -$size * 0.48, $w, $h)
        $g.Restore($state)
    }
    $r = $size * 0.2
    $g.FillEllipse($gold, $c - $r, $c - $r, $r * 2, $r * 2)
    $g.Dispose()
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    return ,$ms.ToArray()
}

$sizes = 16, 24, 32, 48, 64, 256
$images = foreach ($s in $sizes) { ,(New-FlowerPng $s) }
$target = Join-Path $PSScriptRoot '..\assets\feverfew.ico'
New-Item -ItemType Directory -Force (Split-Path $target) | Out-Null
$out = [System.IO.File]::Create($target)
$w = New-Object System.IO.BinaryWriter $out
$w.Write([uint16]0); $w.Write([uint16]1); $w.Write([uint16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $dim = if ($sizes[$i] -ge 256) { 0 } else { $sizes[$i] }
    $w.Write([byte]$dim); $w.Write([byte]$dim); $w.Write([byte]0); $w.Write([byte]0)
    $w.Write([uint16]1); $w.Write([uint16]32)
    $w.Write([uint32]$images[$i].Length); $w.Write([uint32]$offset)
    $offset += $images[$i].Length
}
foreach ($img in $images) { $w.Write($img) }
$w.Dispose()
