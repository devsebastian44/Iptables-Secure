# Guía de Seguridad - Iptables Secure Manager

## Advertencia Ética Importante

⚠️ **Este proyecto es para fines educativos exclusivamente**  
⚠️ **Prohibido su uso en sistemas no autorizados**  
⚠️ **El usuario es responsable del cumplimiento de las leyes locales**

---

## Principios de Seguridad

### 1. Principio de Mínimo Privilegio
- **Ejecución**: Solo con permisos root absolutamente necesarios
- **Alcance**: Operaciones específicas y limitadas
- **Validación**: Verificación constante de privilegios

### 2. Defensa en Profundidad
- **Capas múltiples**: Validación, confirmación, backup
- **Redundancia**: Múltiples mecanismos de protección
- **Monitoreo**: Logging completo de todas las operaciones

### 3. Transparencia y Auditoría
- **Registro**: Cada acción queda documentada
- **Trazabilidad**: Logs con timestamps detallados
- **Responsabilidad**: Claridad en cada operación

---

## Medidas de Seguridad Implementadas

### Validación de Entradas

#### IPs
```python
# Patrón regex estricto
patron = r'^(\d{1,3}\.){3}\d{1,3}$'

# Validación de rango numérico
octetos = ip.split('.')
return all(0 <= int(octeto) <= 255 for octeto in octetos)
```

#### Puertos
```python
# Validación de rango válido
try:
    puerto_num = int(puerto)
    return 1 <= puerto_num <= 65535
except ValueError:
    return False
```

### Prevención de Inyección

#### Comandos Seguros
```python
def ejecutar_comando(comando_lista, mostrar_salida=True):
    try:
        resultado = subprocess.run(
            comando_lista,
            shell=False,  # ✅ Ejecución sin shell (segura)
            check=True,
            capture_output=True,
            text=True
        )
```

#### Sanitización de Entradas
- **Validación previa**: Antes de cualquier ejecución
- **Escape de caracteres**: Prevenir inyección
- **Whitelist**: Solo valores permitidos

### Sistema de Backups

#### Automático
```python
def crear_backup():
    timestamp = datetime.now().strftime('%Y%n%d_%H%M%S')
    backup_file = f"iptables_backup_{timestamp}.rules"
    
    with open(backup_file, "w") as f:
        subprocess.run(["iptables-save"], stdout=f, check=True)
    log(f"Backup creado: {backup_file}")
    return backup_file
```

#### Restauración Segura
- **Confirmación explícita**: Doble verificación del usuario
- **Validación de integridad**: Verificación del backup
- **Rollback automático**: Reversión en caso de error

---

## Análisis de Amenazas

### Amenazas Mitigadas

#### 1. SYN Flood Attacks
- **Técnica**: Limitación de conexiones SYN
- **Implementación**: `iptables -m limit --limit 5/s`
- **Efectividad**: Alta para ataques básicos

#### 2. Port Scanning
- **Detección**: Identificación de patrones de escaneo
- **Bloqueo**: Cadena SCANNER_PROTECTION
- **Tipos detectados**: NULL, FIN, XMAS, SYN-RST

#### 3. SSH Brute Force
- **Prevención**: Restricción por IP
- **Whitelist**: Solo IPs autorizadas
- **Monitoreo**: Registro de intentos

#### 4. DoS HTTP
- **Limitación**: Conexiones simultáneas
- **Rate limiting**: Nuevas conexiones por minuto
- **Configuración**: Personalizable según necesidades

### Amenazas Consideradas

#### 1. Inyección de Comandos
- **Mitigación**: Validación estricta de entradas
- **Sanitización**: Escape de caracteres especiales
- **Validación**: Patrones regex restrictivos

#### 2. Escalada de Privilegios
- **Prevención**: Verificación constante de root
- **Limitación**: Operaciones específicas
- **Auditoría**: Registro de todas las acciones

#### 3. Denegación de Servicio
- **Protección**: Límites de conexión
- **Monitoreo**: Detección de patrones anómalos
- **Respuesta**: Bloqueo automático

---

## Configuración Segura

### 1. Entorno de Ejecución

#### Permisos
```bash
# Verificar usuario actual
whoami

# Ejecutar solo con sudo
sudo python3 src/Iptables.py
```

#### Variables de Entorno
```bash
# Archivo de log seguro
export LOG_FILE="/var/log/iptables_secure.log"

# Directorio de backups
export BACKUP_DIR="/etc/iptables/backups/"
```

### 2. Reglas por Defecto

#### Políticas Base
```bash
# Política por defecto: DROP
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Permitir loopback
iptables -A INPUT -i lo -j ACCEPT

# Permitir conexiones establecidas
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
```

#### Reglas Específicas
```bash
# SSH (solo IPs autorizadas)
iptables -A INPUT -p tcp --dport 22 -s 192.168.1.100 -j ACCEPT

# HTTP/HTTPS
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
```

---

## Monitoreo y Detección

### 1. Logs de Seguridad

#### Formato Estructurado
```
[TIMESTAMP] OPERATION: description
[TIMESTAMP] IP_BLOCKED: 192.168.1.200 - Reason: port scanning
[TIMESTAMP] SSH_ALLOWED: 192.168.1.100 - User: admin
```

#### Análisis de Logs
```bash
# Intentos de conexión fallidos
grep "SSH_DENIED" /var/log/iptables_secure.log

# IPs bloqueadas recientemente
grep "IP_BLOCKED" /var/log/iptables_secure.log | tail -10

# Cambios en reglas
grep "RULE_CHANGE" /var/log/iptables_secure.log
```

### 2. Métricas de Seguridad

#### Indicadores Clave
- **Intentos bloqueados**: Por tipo de ataque
- **Conexiones permitidas**: Por servicio
- **Cambios de configuración**: Frecuencia y autor
- **Backups creados**: Frecuencia y tamaño

#### Alertas
```bash
# Script de monitoreo
#!/bin/bash
# Alerta si hay más de 10 bloqueos en una hora
BLOCKED_COUNT=$(grep "IP_BLOCKED" /var/log/iptables_secure.log | grep "$(date '+%Y-%m-%d %H')" | wc -l)
if [ $BLOCKED_COUNT -gt 10 ]; then
    echo "ALERTA: Alto número de bloqueos: $BLOCKED_COUNT"
fi
```

---

## Testing de Seguridad

### 1. Tests Automatizados

#### Validación de Entradas
```python
def test_injection_prevention():
    inputs_maliciosos = [
        "192.168.1.1; rm -rf /",
        "192.168.1.1 && cat /etc/passwd",
        "$(whoami)",
        "`id`"
    ]
    
    for input_malicioso in inputs_maliciosos:
        assert not validar_ip(input_malicioso)
```

#### Análisis Estático
```bash
# Bandit - Security Linter
bandit -r src/ -f json -o security-report.json

# Safety - Dependencies check
safety check
```

### 2. Tests de Penetración Ética

#### Escenarios de Prueba
- **Inyección SQL**: Intentos de inyección en validaciones
- **Command Injection**: Pruebas de inyección de comandos
- **Privilege Escalation**: Intentos de escalada de privilegios
- **DoS Attacks**: Pruebas controladas de denegación de servicio

---

## Respuesta a Incidentes

### 1. Detección

#### Indicadores de Compromiso
- **Logs anómalos**: Patrones inusuales en logs
- **Cambios no autorizados**: Modificaciones de reglas
- **Fallo en backups**: Errores en creación de backups
- **Alta carga**: Uso inusual de recursos

### 2. Contención

#### Acciones Inmediatas
```bash
# Bloquear IP sospechosa
iptables -I INPUT -s SUSPICIOUS_IP -j DROP

# Guardar estado actual
iptables-save > emergency_backup.rules

# Revisar reglas activas
iptables -L -n --line-numbers
```

### 3. Recuperación

#### Restauración
```bash
# Restaurar desde backup
iptables-restore < last_known_good.rules

# Verificar estado
iptables -L -n

# Registrar incidente
echo "[TIMESTAMP] INCIDENT_RESTORED: description" >> /var/log/iptables_secure.log
```

---

## Mejoras Continuas

### 1. Actualizaciones de Seguridad
- **Parches regulares**: Mantener sistema actualizado
- **Revisión de código**: Análisis periódico de vulnerabilidades
- **Testing continuo**: Integración en CI/CD

### 2. Monitoreo Proactivo
- **Análisis de tendencias**: Identificar patrones anómalos
- **Inteligencia de amenazas**: Incorporar nuevos vectores de ataque
- **Métricas avanzadas**: Indicadores predictivos

---

## Conclusión

Iptables Secure Manager implementa múltiples capas de seguridad siguiendo mejores prácticas DevSecOps. Sin embargo, la seguridad es un proceso continuo que requiere:

1. **Vigilancia constante** de logs y métricas
2. **Actualización regular** de componentes y reglas
3. **Testing periódico** de controles de seguridad
4. **Mejora continua** basada en lecciones aprendidas

**Recordatorio ético**: Esta herramienta debe usarse únicamente para fines educativos y en sistemas propios o con autorización explícita.

---

*Para reportes de vulnerabilidades o sugerencias de seguridad, contactar a través de los canales oficiales del proyecto.*
