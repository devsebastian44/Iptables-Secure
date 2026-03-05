# 🛡️ Iptables-Secure: Gestión Profesional de Cortafuegos

![Python](https://img.shields.io/badge/Python-3.9+-blue?logo=python&logoColor=white)
![GitLab](https://img.shields.io/badge/GitLab-Repository-orange?logo=gitlab)
![License](https://img.shields.io/badge/License-GPL--3.0-red)
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

## 🚀 Instalación y Acceso

> [!IMPORTANT]
> El repositorio completo con todo el código funcional está disponible en **GitLab** para acceso completo.

https://gitlab.com/group-cybersecurity-lab/Iptables-Secure


## 🚀 Configuración Profesional

### Requisitos

- **SO**: Linux (Debian/Ubuntu recomendado)
- **Lenguaje**: Python 3.8 o superior
- **Privilegios**: Se requieren permisos de Root/Sudo para manipular el cortafuegos.


### Inicio Rápido (Versión Educativa)

1. Clonar el repositorio:

   ```bash
   git clone https://gitlab.com/group-cybersecurity-lab/Iptables-Secure
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

## 🔬 CI/CD y Pruebas (Laboratorio Público GitLab)

El repositorio completo con pipelines de DevSecOps está disponible en **GitLab** como laboratorio público:

### Pipeline de Integración Continua

- **Pruebas Automatizadas**: Suite completa con `pytest` incluyendo tests unitarios, funcionales y de integración
- **Seguridad Estática**: Análisis SAST con `bandit` para detectar vulnerabilidades y malas prácticas
- **Validación de Infraestructura**: Tests de configuración de reglas iptables en entorno aislado
- **Documentación Automática**: Generación de reportes y cobertura de código

### Entorno de Laboratorio

El laboratorio GitLab proporciona:
- **Código Fuente Completo**: Toda la lógica funcional de gestión de cortafuegos
- **Configuraciones de Testing**: Entornos de prueba automatizados y validación de reglas
- **Scripts de Automatización**: Herramientas de despliegue y configuración segura
- **Integración Continua**: Pipeline completo que valida cada cambio automáticamente

El laboratorio público permite análisis completo del código, ejecución de pruebas y estudio de las mejores prácticas de DevSecOps aplicadas a herramientas de seguridad de red.
