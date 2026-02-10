# =============================================================================
# Script para Publicación en GitHub (Portafolio Público)
# Iptables Secure Manager - DevSecOps
# =============================================================================

param(
    [Parameter(Mandatory=$false)]
    [string]$Message = "🚀 Actualización de portafolio público"
)

Write-Host "🔧 Preparando publicación para GitHub público..." -ForegroundColor Green

# Verificar que estamos en la rama correcta
$branch = git rev-parse --abbrev-ref HEAD
if ($branch -ne "main") {
    Write-Host "❌ Error: Debes estar en la rama 'main'" -ForegroundColor Red
    exit 1
}

# Limpiar archivos sensibles para GitHub público
Write-Host "🧹 Limpiando archivos sensibles..." -ForegroundColor Yellow

# Eliminar logs y backups
Remove-Item -Path "*.log" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "*.rules" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "iptables_backup_*" -Force -ErrorAction SilentlyContinue

# Limpiar cache de Python
Remove-Item -Path "__pycache__" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "*.pyc" -Force -ErrorAction SilentlyContinue

# Limpiar archivos temporales
Remove-Item -Path ".pytest_cache" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path ".coverage" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "htmlcov" -Recurse -Force -ErrorAction SilentlyContinue

# Verificar estructura mínima para GitHub
$requiredFiles = @(
    "README.md",
    "src/Iptables.py",
    "docs/LICENSE",
    "docs/architecture.md",
    "docs/security-guide.md",
    "configs/setup.cfg"
)

Write-Host "📋 Verificando estructura mínima..." -ForegroundColor Yellow
foreach ($file in $requiredFiles) {
    if (Test-Path $file) {
        Write-Host "✅ $file" -ForegroundColor Green
    } else {
        Write-Host "❌ $file - ARCHIVO FALTANTE" -ForegroundColor Red
        exit 1
    }
}

# Agregar cambios al staging
Write-Host "📦 Agregando archivos al staging..." -ForegroundColor Yellow
git add README.md
git add src/
git add docs/
git add configs/
git add diagrams/
git add .gitignore
git add .gitlab-ci.yml

# Excluir archivos sensibles del staging
git reset HEAD *.log 2>$null
git reset HEAD *.rules 2>$null
git reset HEAD iptables_backup_* 2>$null
git reset HEAD tests/ 2>$null

# Verificar qué se va a commitear
Write-Host "🔍 Archivos que se van a commitear:" -ForegroundColor Cyan
git status --porcelain

# Confirmar antes de commit
$confirm = Read-Host "¿Confirmar commit para GitHub público? (S/N)"
if ($confirm -notmatch "^[Ss]$") {
    Write-Host "❌ Operación cancelada" -ForegroundColor Red
    exit 0
}

# Hacer commit
Write-Host "💾 Creando commit..." -ForegroundColor Yellow
git commit -m $Message

# Push a GitHub
Write-Host "🚀 Subiendo a GitHub..." -ForegroundColor Yellow
git push origin main

Write-Host "✅ Publicación completada exitosamente" -ForegroundColor Green
Write-Host "🌐 Repositorio: https://github.com/devsebastian44/Iptables-Secure" -ForegroundColor Cyan

# Mostrar estadísticas
Write-Host "📊 Estadísticas del repositorio:" -ForegroundColor Yellow
git log --oneline -5

Write-Host "🎈 Portafolio público actualizado" -ForegroundColor Green
