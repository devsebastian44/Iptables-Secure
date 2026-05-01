# 🛡️ Iptables-Secure

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat&logo=python&logoColor=white)
![iptables](https://img.shields.io/badge/iptables-Firewall%20Manager-E95420?style=flat&logo=linux&logoColor=white)
![Bandit](https://img.shields.io/badge/SAST-Bandit-critical?style=flat&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-GPL--3.0-red?style=flat&logo=gnu&logoColor=white)
![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-CI%2FCD-2088FF?style=flat&logo=github-actions&logoColor=white)

---

## 🧠 Overview

**Iptables-Secure** es una herramienta de hardening de red escrita íntegramente en Python (100%), diseñada para automatizar la configuración y el endurecimiento del cortafuegos `iptables` en sistemas Linux. A través del script principal `src/Iptables.py`, ejecutado con privilegios de root, el sistema aplica un conjunto estructurado de reglas de filtrado de paquetes orientadas a mitigar los vectores de ataque de red más comunes en servidores de producción.

La herramienta genera automáticamente respaldos de las reglas activas (`iptables_backup_*.rules`) antes de aplicar cualquier cambio, manteniendo una bitácora de auditoría en archivos de log — ambos excluidos de Git para proteger la configuración sensible del servidor. Las reglas aplicadas incluyen mitigación de SYN flooding, bloqueo de escaneos sigilosos, restricción de acceso SSH y persistencia de reglas mediante `iptables-persistent`.

El proyecto está diseñado como una solución profesional de seguridad de red, integrando mejores prácticas de DevSecOps como análisis estático de seguridad (SAST), linting y pruebas automatizadas para garantizar un despliegue robusto.

> ⚠️ **Uso Responsable:** Esta herramienta modifica reglas de firewall activas en el sistema. Su uso incorrecto puede bloquear acceso legítimo al servidor. Probar siempre en entornos controlados antes de desplegar en producción.
>
> ---
>
> 🛡️ **Security Disclaimer:** This project is for educational and ethical cybersecurity purposes only. The author is not responsible for any damage caused by misuse of this tool.

---

## ⚙️ Features

- **Automatización de reglas iptables** mediante Python puro — elimina la necesidad de escribir reglas manualmente en la línea de comandos
- **Mitigación de SYN Flood** — limitación de tasa de paquetes SYN entrantes para prevenir el agotamiento del stack TCP del servidor
- **Hardening de SSH** — restricción de acceso al puerto 22 a direcciones IP específicas y allowlist configurable
- **Prevención de DoS** — límites de conexiones concurrentes en puertos web (80/443) para contener ataques de denegación de servicio
- **Bloqueo de escaneos sigilosos** — detección y descarte de paquetes con combinaciones de flags TCP anómalas: XMAS scan (FIN+PSH+URG), NULL scan (sin flags) y FIN scan
- **Sistema de backup automático** — generación de `iptables_backup_*.rules` con las reglas activas previas a cualquier modificación, garantizando rollback seguro
- **Registro de auditoría** — bitácora detallada en `iptables_rules.log` con cada cambio de regla aplicado
- **Persistencia de reglas** — integración con `iptables-persistent` para que las reglas sobrevivan reinicios del sistema
- **Configuración multi-entorno** — soporte para perfiles `.env.local`, `.env.development`, `.env.test`, `.env.production` con parámetros por contexto de despliegue
- **Pipeline CI/CD profesional** con linting (`flake8`), análisis SAST (`bandit`), linting de scripts (`shellcheck`) y suite de pruebas (`pytest`) con cobertura

---

## 🛠️ Tech Stack

### Lenguaje y entorno

| Componente | Tecnología | Propósito |
|---|---|---|
| Lenguaje | Python 3.8+ (100%) | Lógica principal de orquestación de reglas |
| Firewall | iptables (Linux kernel) | Motor de filtrado de paquetes de red |
| Persistencia | iptables-persistent | Retención de reglas entre reinicios del sistema |
| SO objetivo | Linux (Debian / Ubuntu) | Plataforma de ejecución requerida |

### Pipeline de calidad y seguridad

| Herramienta | Categoría | Propósito |
|---|---|---|
| `flake8` | Linting | Verificación de estilo PEP 8 en el código Python |
| `bandit` | SAST | Detección de patrones de código peligrosos en Python |
| `shellcheck` | Linting | Análisis estático de scripts Bash auxiliares |
| `pytest` | Testing | Suite de pruebas unitarias, funcionales y de integración |
| `coverage.py` | Cobertura | Medición de cobertura de código en los tests |
| `tox` / `nox` | Multi-env | Ejecución de tests en múltiples versiones de Python |

### Gestión de secretos y configuración (inferido del `.gitignore`)

| Patrón excluido | Significado |
|---|---|
| `*.key`, `*.pem`, `*.crt`, `*.p12` | Soporte para certificados y claves privadas en configuración |
| `secrets.yaml`, `secrets.json` | Archivos de credenciales y parámetros sensibles por entorno |
| `credentials/`, `.secrets/` | Directorios de secretos para integración con servicios externos |
| `config.ini`, `settings.local.py` | Configuraciones locales del sistema que no deben versionarse |
| `iptables_backup_*.rules` | Respaldos automáticos de reglas generados en cada ejecución |
| `iptables_rules.log` | Bitácora de auditoría de cambios en el cortafuegos |

---

## 📦 Installation

### Requisitos previos

- **Sistema operativo:** Linux — Debian / Ubuntu (recomendado)
- **Python:** 3.8 o superior
- **Privilegios:** `root` o `sudo` — requeridos para manipular `iptables`
- **Dependencia del sistema:** `iptables` y `iptables-persistent`

### Clonar el repositorio

```bash
git clone https://github.com/devsebastian44/Iptables-Secure.git
cd Iptables-Secure
```

### Instalar dependencias del sistema

```bash
# Instalar iptables-persistent para reglas permanentes
sudo apt update && sudo apt install -y iptables-persistent

# Instalar dependencias Python
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Configurar el entorno local

```bash
# Copiar plantilla de configuración para el entorno deseado
cp .env.example .env.local
nano .env.local   # Definir IPs permitidas para SSH, puertos, límites de conexión
```

### Instalar herramientas de análisis y testing (CI local)

```bash
# Instalar dependencias centralizadas de desarrollo, linting y seguridad
pip install -r requirements-dev.txt

# Linting para scripts Bash (Opcional)
sudo apt install shellcheck
```

---

## ▶️ Usage

### Ejecutar el gestor de cortafuegos

```bash
# Requiere privilegios de root
sudo python3 src/Iptables.py
```

El script aplica el conjunto completo de reglas de hardening en la siguiente secuencia:

1. **Backup automático** — exporta las reglas `iptables` activas a `iptables_backup_<timestamp>.rules`
2. **Flush de reglas existentes** — limpia las cadenas INPUT, OUTPUT y FORWARD para aplicar un estado conocido
3. **Política por defecto** — establece DROP como política base en la cadena INPUT
4. **Aplicación de reglas** — configura las protecciones específicas (SYN flood, SSH, DoS, port scans)
5. **Persistencia** — guarda las reglas mediante `iptables-persistent` para sobrevivir reinicios
6. **Log de auditoría** — registra cada cambio en `iptables_rules.log`

### Flujo de reglas aplicadas

```
Paquete entrante
       │
       ▼
┌──────────────────┐     DROP
│  NULL scan?      │──────────►  /dev/null
│  XMAS scan?      │
│  FIN scan?       │
└──────────────────┘
       │ No
       ▼
┌──────────────────┐     LIMIT
│  SYN Flood?      │──────────►  --limit 1/s --limit-burst 3
└──────────────────┘
       │ OK
       ▼
┌──────────────────┐     ACCEPT / DROP
│  SSH (port 22)?  │──────────►  Solo IPs en allowlist
└──────────────────┘
       │
       ▼
┌──────────────────┐     LIMIT
│  DoS web?        │──────────►  connlimit por IP en 80/443
│  (port 80/443)   │
└──────────────────┘
       │ OK
       ▼
    ACCEPT
```

### Revertir a las reglas anteriores

```bash
# Restaurar backup generado automáticamente
sudo iptables-restore < iptables_backup_<timestamp>.rules
```

### Ejecutar el pipeline de calidad localmente

```bash
# Linting Python
flake8 src/

# Análisis SAST
bandit -r src/

# Linting Bash
shellcheck scripts/*.sh

# Tests con cobertura
pytest tests/ -v --cov=src --cov-report=html

# Multi-entorno con tox
tox
```

---

## 📁 Project Structure

```
Iptables-Secure/
│
├── src/                               # Código fuente principal
│   └── Iptables.py                    # Script central — gestor de reglas iptables
│
├── scripts/                           # Automatización DevSecOps
│   └── *.sh                           # Scripts auxiliares de configuración y CI
│
├── configs/                           # Perfiles de configuración por entorno
│   ├── .env.example                   # Plantilla pública de variables de entorno
│   ├── .env.local                     # Config local [gitignoreado]
│   ├── .env.development               # Config desarrollo [gitignoreado]
│   ├── .env.test                      # Config testing [gitignoreado]
│   └── .env.production                # Config producción [gitignoreado]
│
├── tests/                             # Suite de pruebas pytest
│   └── test_*.py                      # Tests unitarios, funcionales y de integración
│
├── docs/                              # Documentación técnica
│   └── *.md                           # Manuales de reglas y arquitectura
│
├── diagrams/                          # Diagramas de flujo de paquetes y arquitectura
│   └── *.md                           # Representaciones del pipeline de filtrado
│
├── backups/                           # Respaldos de reglas generados [gitignoreado]
│   └── iptables_backup_*.rules        # Exportaciones automáticas pre-cambio
│
├── logs/                              # Bitácora de auditoría [gitignoreado]
│   └── iptables_rules.log             # Registro de cambios aplicados al cortafuegos
│
├── data/
│   ├── raw/                           # Datos crudos de red [gitignoreado]
│   └── processed/                     # Datos procesados para análisis [gitignoreado]
│
├── .gitignore                         # 156 líneas — 9 secciones de exclusión categorizadas
├── LICENSE                            # GNU General Public License v3.0
└── README.md
```

> **Nota sobre el `.gitignore`:** Con 156 líneas organizadas en 9 secciones categorizadas (archivos sensibles de ciberseguridad, logs/backups, entornos virtuales, IDE, configuraciones sensibles, testing/coverage, documentación temporal, artefactos CI/CD y datasets), este archivo refleja una gestión de secretos de grado profesional. Ningún log, backup de reglas, certificado, credencial ni configuración de entorno puede ser expuesto accidentalmente al repositorio público.

---

## 🔐 Security

### Protecciones implementadas

| Vector de ataque | Técnica iptables | Implementación |
|---|---|---|
| **SYN Flood** | Rate limiting | `--syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT` |
| **NULL Scan** | Flag matching | `-p tcp --tcp-flags ALL NONE -j DROP` |
| **XMAS Scan** | Flag matching | `-p tcp --tcp-flags ALL ALL -j DROP` |
| **FIN Scan** | Flag matching | `-p tcp --tcp-flags ALL FIN -j DROP` |
| **Fuerza bruta SSH** | IP allowlist | `-p tcp --dport 22 -s <IP_AUTORIZADA> -j ACCEPT` |
| **DoS web** | Connection limit | `-p tcp --dport 80 -m connlimit --connlimit-above N -j DROP` |

### Consideraciones de seguridad operacional

- **Backup antes de cada cambio:** El script genera `iptables_backup_<timestamp>.rules` automáticamente antes de modificar cualquier regla — esto garantiza un punto de restauración ante configuraciones incorrectas
- **Política DROP por defecto:** La cadena INPUT se configura con `POLICY DROP`, lo que significa que solo el tráfico explícitamente permitido puede ingresar al servidor
- **Secretos protegidos por `.gitignore`:** Certificados (`*.pem`, `*.key`, `*.crt`, `*.p12`), credenciales (`secrets.yaml`, `secrets.json`) y configuraciones de entorno nunca se sincronizan al repositorio
- **SAST en pipeline:** `bandit` analiza el código Python detectando uso peligroso de `subprocess`, `eval` o llamadas shell inseguras
- **Logs de auditoría gitignoreados:** Los archivos `iptables_rules.log` y `logs/` registran cambios de firewall pero nunca exponen la topología del servidor

### Buenas prácticas antes de desplegar

- Probar en una VM o servidor de staging que **no sea producción**
- Verificar que la IP desde la cual se conecta por SSH está en la allowlist **antes** de aplicar las reglas
- Conservar siempre el backup `iptables_backup_*.rules` generado para poder revertir
- En caso de bloqueo accidental, acceder físicamente o por consola de emergencia del proveedor cloud para limpiar las reglas con `sudo iptables -F`

---

## 🌐 Repository Architecture

Este proyecto sigue una arquitectura centralizada orientada a la seguridad y transparencia del código fuente en GitHub.

```
GitHub (Repositorio Central)
┌──────────────────────────────┐
│ src/Iptables.py  → Lógica    │
│ configs/         → Plantillas│
│ tests/           → Tests     │
│ docs/            → Documentos│
│ logs/ backups/   → Locales   │
│ LICENSE / README.md          │
└──────────────────────────────┘
```

---

## 🚀 Roadmap

- [ ] **Interfaz CLI interactiva** — Menú de selección de módulos de protección
- [ ] **Soporte para IPv6** — Extensión de todas las reglas a `ip6tables`
- [ ] **Módulo de detección de anomalías** — Análisis de los logs para identificar patrones de ataque
- [ ] **Perfiles de hardening predefinidos** — Conjuntos de reglas por tipo de servidor
- [ ] **Integración con `fail2ban`** — Baneos dinámicos de IPs
- [ ] **Soporte para `nftables`** — Migración opcional del backend de filtrado

---

## 📄 License

**GNU General Public License v3.0** — Ver [`LICENSE`](./LICENSE)

El código puede ser usado, modificado y distribuido bajo los términos de la GPL-3.0, con la obligación de mantener el código fuente disponible en distribuciones derivadas.

---

## 🤝 Contributing

¡Las contribuciones son bienvenidas! Si tienes ideas para nuevas reglas de hardening o mejoras en el motor de Python, por favor lee nuestra [Guía de Contribución](./docs/CONTRIBUTING.md) antes de enviar un Pull Request.

1. Fork del proyecto
2. Crear una rama (`feature/increible-mejora`)
3. Commit de tus cambios (`feat: add amazing feature`)
4. Push a la rama (`git push origin feature/increible-mejora`)
5. Abrir un Pull Request

---

## 👨‍💻 Author

**Sebastian** — [`@devsebastian44`](https://github.com/devsebastian44)

Desarrollador e investigador en ciberseguridad con especialización en hardening de infraestructura, automatización de políticas de red y pipelines DevSecOps.

| Plataforma | Enlace |
|---|---|
| GitHub | [github.com/devsebastian44](https://github.com/devsebastian44) |

---

> *Este repositorio es un portafolio educativo de hardening de red. Todo el contenido está diseñado para su uso en entornos de laboratorio controlados y servidores con autorización explícita del administrador del sistema.*