# publish_public.ps1
# Script para sincronizar el trabajo de 'main' (Lab) al Portafolio Público (GitHub)

Write-Host "[*] Iniciando sincronización de Portafolio..." -ForegroundColor Cyan

# 1. Asegurar que estamos en main y todo está guardado
$currentBranch = git rev-parse --abbrev-ref HEAD
if ($currentBranch -ne "main") {
    Write-Host "[!] No estás en la rama 'main'. Cambiando a 'main'..." -ForegroundColor Yellow
    git checkout main
}

$status = git status --porcelain
if ($status) {
    Write-Error "Error: Tienes cambios sin guardar en 'main'. Haz commit antes de publicar."
    exit
}

Write-Host "[*] Sincronizando con GitLab (Privado)..."
git pull gitlab main --rebase
git push gitlab main

# 2. Resetear la rama pública desde main
Write-Host "[*] Preparando rama 'public'..."
git checkout -B public main

# 3. Limpieza de seguridad profesional (Archivos que NO van a GitHub)
Write-Host "[*] Aplicando filtros de seguridad..." -ForegroundColor Yellow

# Eliminar carpetas privadas y configuración de CI/CD
git rm -r --cached tests/ -f 2>$null
git rm -r --cached configs/ -f 2>$null
git rm -r --cached scripts/ -f 2>$null
git rm --cached .gitlab-ci.yml -f 2>$null

# 4. Confirmar limpieza y subir
git commit -m "docs: release update to public portfolio" --allow-empty
Write-Host "[*] Subiendo a GitHub (Público)..." -ForegroundColor Green
# Push a la rama main de GitHub (origin) desde nuestra rama local public
git push origin public:main --force

# 5. Volver al laboratorio
Write-Host "[*] Volviendo a la rama 'main' (Lab)..."
git clean -fd 2>$null
git checkout main -f

Write-Host "[🎉] ¡Portafolio actualizado con éxito!" -ForegroundColor Green