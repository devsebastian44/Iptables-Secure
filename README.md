# 🛡️ Iptables-Secure: Gestión Profesional de Cortafuegos

![Python](https://img.shields.io/badge/Python-3.9+-blue?logo=python&logoColor=white)
![GitLab](https://img.shields.io/badge/GitLab-Repository-orange?logo=gitlab)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Status](https://img.shields.io/badge/Status-Stable-brightgreen)

## 📌 Descripción del Proyecto
**Iptables-Secure** es una herramienta profesional de DevSecOps diseñada para automatizar la configuración de reglas de `iptables` en sistemas Linux. Se enfoca en el endurecimiento (hardening) de servidores contra ataques de red comunes como inundaciones SYN (SYN flooding), DoS y escaneos de puertos no autorizados.

Este proyecto está estructurado como un **Portafolio Profesional** para GitHub y un **Laboratorio Privado** para GitLab, demostrando código limpio, pruebas automatizadas y gestión de infraestructura segura.

---

## ⚖️ Divulgación Ética
> [!IMPORTANT]
> Esta herramienta está destinada únicamente a **fines educativos y defensivos**. El objetivo es ayudar a los administradores de sistemas e ingenieros de seguridad a comprender e implementar técnicas de endurecimiento de red. El uso inadecuado puede resultar en el bloqueo accidental de sus propios servidores.

---

## 📂 Estructura del Repositorio
```bash
.
├── src/          # Lógica principal de la aplicación
├── docs/         # Documentación profesional y licencias
├── diagrams/     # Diagramas de arquitectura y flujo
├── configs/      # Configuraciones de herramientas y entorno
├── scripts/      # [Privado] Scripts de automatización y configuración
├── tests/        # [Privado] Pruebas unitarias y de lógica
└── .gitlab-ci.yml# [Privado] Configuración del pipeline de CI/CD
```

---

## 🚀 Configuración Profesional

### Requisitos
- **SO**: Linux (Debian/Ubuntu recomendado)
- **Lenguaje**: Python 3.8 o superior
- **Privilegios**: Se requieren permisos de Root/Sudo para manipular el cortafuegos.

### Inicio Rápido (Versión Educativa)
1. Clonar el repositorio:

   ```bash
   git clone https://github.com/Devsebastian44/Iptables-Secure.git
   cd Iptables-Secure
   ```
2. Ejecutar el protector:

   ```bash
   sudo python3 src/Iptables.py
   ```

---

## 🛠️ Características Principales
- **Protección SYN Flood**: Limita la tasa de paquetes SYN para prevenir el agotamiento de recursos.
- **Endurecimiento de SSH**: Restringe el acceso a direcciones IP específicas.
- **Prevención de DoS**: Implementa límites de conexión en puertos web.
- **Mitigación de Escaneo de Puertos**: Bloquea comportamientos típicos de escaneo (XMAS, NULL, FIN scans).
- **Reglas Persistentes**: Integración con `iptables-persistent`.

---

## 🔬 CI/CD y Pruebas (Exclusivo de Laboratorio)
En el laboratorio privado (GitLab), este proyecto utiliza un pipeline completo de DevSecOps:
- **Linting**: Cumplimiento de calidad de código mediante `flake8`.
- **Pruebas Unitarias**: Validación de lógica usando `pytest`.
- **Escaneo de Seguridad**: Análisis estático con `bandit`.
