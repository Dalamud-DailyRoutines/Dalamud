param(
    [Parameter(Mandatory = $true)]
    [string] $ReleasePath,

    [Parameter(Mandatory = $true)]
    [string] $OutputPath
)

$releaseRoot = (Resolve-Path -LiteralPath $ReleasePath).Path
$outputRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)

if (Test-Path -LiteralPath $outputRoot) {
    Remove-Item -LiteralPath $outputRoot -Recurse -Force
}

New-Item -ItemType Directory -Path $outputRoot | Out-Null

$hashesPath = Join-Path $releaseRoot "hashes.json"

if (-not (Test-Path -LiteralPath $hashesPath)) {
    throw "未找到 hashes.json"
}

$hashes = Get-Content -LiteralPath $hashesPath -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable
$assetNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$files = [System.Collections.Generic.List[object]]::new()

foreach ($entry in $hashes.GetEnumerator() | Sort-Object Name) {
    $relativePath = $entry.Key.Replace("\", "/")
    $hash = [string] $entry.Value
    $sourcePath = Join-Path $releaseRoot $relativePath

    if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
        throw "清单引用的文件不存在: $relativePath"
    }

    $assetName = "dalamud-file-$hash.bin"

    if ($assetNames.Add($assetName)) {
        Copy-Item -LiteralPath $sourcePath -Destination (Join-Path $outputRoot $assetName)
    }

    $file = Get-Item -LiteralPath $sourcePath

    $files.Add([ordered] @{
        path = $relativePath
        hash = $hash
        size = $file.Length
        asset = $assetName
    })
}

$manifest = [ordered] @{
    version = 1
    hashAlgorithm = "MD5"
    packageAsset = "latest.7z"
    hashesAsset = "hashes.json"
    files = $files
}

$json = $manifest | ConvertTo-Json -Depth 8
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllText((Join-Path $outputRoot "manifest.json"), $json + "`n", $utf8NoBom)
