$ErrorActionPreference = "SilentlyContinue"

Get-Process node | Stop-Process -Force
Get-Process mysqld | Stop-Process -Force

Write-Host "CRM backend processes stop kar diye gaye."
