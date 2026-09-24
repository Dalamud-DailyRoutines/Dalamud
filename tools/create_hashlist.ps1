param(
    [Parameter(Mandatory = $true)]
    [string] $ReleasePath
)

$hashes = [ordered]@{}
$releaseRoot = (Resolve-Path -LiteralPath $ReleasePath).Path

Push-Location -LiteralPath $releaseRoot

try {
    Get-ChildItem -File -Recurse -Exclude dalamud.txt,hashes.json,manifest.json,*.zip,*.7z,*.pdb,*.ipdb | Foreach-Object {
        $key = ($_.FullName | Resolve-Path -Relative).TrimStart(".\\")
        $val = (Get-FileHash $_.FullName -Algorithm MD5).Hash
        $hashes.Add($key, $val)
    }

    $json = $hashes | ConvertTo-Json
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText((Join-Path $releaseRoot "hashes.json"), $json + "`n", $utf8NoBom)
} finally {
    Pop-Location
}
