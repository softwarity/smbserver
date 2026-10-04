# Copies a folder to the mapped drive with the copy engine of the Explorer
# and checks what the shell then sees. Called by windows.sh, which passes the
# source folder and the drive letter in the environment.
$ErrorActionPreference = 'Stop'
$src = $env:SRC
$drive = $env:DRIVE + ':\'

# What a browser stamps on a download, and the Explorer carries along.
Set-Content -Path (Join-Path $src 'a.txt') -Stream Zone.Identifier -Value '[ZoneTransfer]', 'ZoneId=3'

$shell = New-Object -ComObject Shell.Application
$dst = $shell.NameSpace($drive)
if ($null -eq $dst) { throw 'the shell does not see the drive' }
# 4: no progress window, 16: yes to all, 512: no prompt to create a folder,
# 1024: no error dialog.
$dst.CopyHere($src, 1556)

$copy = Join-Path $drive 'explorer-src'
$deadline = (Get-Date).AddSeconds(90)
while (-not (Test-Path (Join-Path $copy 'sub\b.txt')) -or
       (Get-Item (Join-Path $copy 'blob') -ErrorAction SilentlyContinue).Length -ne 3000000) {
    if ((Get-Date) -gt $deadline) { throw 'the shell copy did not complete' }
    Start-Sleep -Milliseconds 500
}
if ($shell.NameSpace($copy).Items().Count -ne 3) { throw 'the shell does not list three items' }
$zone = Get-Content -Path (Join-Path $copy 'a.txt') -Stream Zone.Identifier
if ($zone -notcontains 'ZoneId=3') { throw 'the zone stream did not follow the file' }
Write-Output 'shell copy verified'
