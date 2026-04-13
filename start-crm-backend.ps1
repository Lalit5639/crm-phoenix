$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$mysqlBase = "C:\mysql84"
$mysqlData = "C:\crm_mysql_data"
$mysqld = Join-Path $mysqlBase "bin\mysqld.exe"
$mysql = Join-Path $mysqlBase "bin\mysql.exe"
$node = "C:\Program Files\nodejs\node.exe"
$nodeLog = Join-Path $projectRoot "node.out.log"
$nodeErr = Join-Path $projectRoot "node.err.log"
$mysqlLog = Join-Path $projectRoot "mysqld.out.log"
$mysqlErr = Join-Path $projectRoot "mysqld.err.log"

if (-not (Test-Path $mysqld)) {
  throw "MySQL not found at $mysqld. Reinstall MySQL or update this script."
}

if (-not (Test-Path $node)) {
  throw "Node.js not found at $node."
}

if (-not (Test-Path $mysqlData)) {
  New-Item -ItemType Directory -Force -Path $mysqlData | Out-Null
}

$mysqlReady = $false
try {
  $tcp = Test-NetConnection -ComputerName 127.0.0.1 -Port 3306 -WarningAction SilentlyContinue
  $mysqlReady = [bool]$tcp.TcpTestSucceeded
} catch {
  $mysqlReady = $false
}

if (-not $mysqlReady) {
  if (-not (Test-Path (Join-Path $mysqlData "mysql"))) {
    & $mysqld --initialize-insecure --basedir=$mysqlBase --datadir=$mysqlData --console *> $null
  }

  Start-Process -FilePath $mysqld `
    -ArgumentList "--basedir=$mysqlBase","--datadir=$mysqlData","--port=3306","--bind-address=127.0.0.1","--console" `
    -RedirectStandardOutput $mysqlLog `
    -RedirectStandardError $mysqlErr `
    -WindowStyle Hidden

  Start-Sleep -Seconds 5
}

$dbStatus = & $mysql -N -h 127.0.0.1 -P 3306 -u root -e "SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME='phoenix_crm';"
if (-not $dbStatus) {
  $sql = "CREATE DATABASE phoenix_crm CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; USE phoenix_crm; SET FOREIGN_KEY_CHECKS=0;`n" + (Get-Content -Raw (Join-Path $projectRoot "database.sql")) + "`nSET FOREIGN_KEY_CHECKS=1;"
  $sql | & $mysql -h 127.0.0.1 -P 3306 -u root
}

Start-Process powershell `
  -ArgumentList "-NoExit","-Command","Set-Location '$projectRoot'; & '$node' server.js" `
  -WorkingDirectory $projectRoot

Write-Host ""
Write-Host "CRM backend start ho gaya."
Write-Host "Open: http://127.0.0.1:5501"
Write-Host "API check: http://127.0.0.1:5501/api/db-status"
