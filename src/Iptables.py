import sys
import os
import subprocess
import re
from datetime import datetime

# Colores
BLUE = '\033[34m'
GREEN = '\033[32m'
RED = '\033[31m'
YELLOW = '\033[33m'
RESET = '\033[0m'
BOLD = '\033[1m'

# Archivo de log
LOG_FILE = "iptables_rules.log"

def limpiar_pantalla():
    """Limpia la pantalla de forma multiplataforma sin usar el shell"""
    if os.name == 'nt':
        os.system('cls')  # nosec
    else:
        print('\033[H\033[J', end='')  # Secuencia ANSI para limpiar pantalla

def banner():
    """Muestra el banner de la aplicación"""
    print("")
    print(f"{BLUE} .___        __        ___.   .__                  {RESET}")
    print(f"{BLUE} |   |______/  |______ \\_ |__ |  |   ____   ______ {RESET}")
    print(f"{BLUE} |   \\____ \\   __\\__  \\ | __ \\|  | _/ __ \\ /  ___/ {RESET}")
    print(f"{BLUE} |   |  |_> >  |  / __ \\| \\_\\ \\  |_\\  ___/ \\___ \\  {RESET}")
    print(f"{BLUE} |___|   __/|__| (____  /___  /____/\\___  >____  > {RESET}")
    print(f"{BLUE}     |__|             \\/    \\/          \\/     \\/  {RESET}")
    print("")

def log(mensaje):
    """Registra acciones en el archivo de log"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {mensaje}\n")

def verificar_root():
    """Verifica si el script se ejecuta como root"""
    if os.geteuid() != 0:
        print(f"{RED}[!]{RESET} Este script debe ejecutarse como root (usando sudo)")
        print(f"{YELLOW}[!]{RESET} Ejemplo: sudo python3 {sys.argv[0]}")
        sys.exit(1)

def validar_ip(ip):
    """Valida formato de dirección IP"""
    patron = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(patron, ip):
        octetos = ip.split('.')
        return all(0 <= int(octeto) <= 255 for octeto in octetos)
    return False

def validar_puerto(puerto):
    """Valida que el puerto esté en el rango válido"""
    try:
        puerto_num = int(puerto)
        return 1 <= puerto_num <= 65535
    except ValueError:
        return False

def ejecutar_comando(comando_lista, mostrar_salida=True):
    """Ejecuta un comando de sistema de forma segura (sin shell)"""
    try:
        if isinstance(comando_lista, str):
            comando_lista = comando_lista.split()

        resultado = subprocess.run(
            comando_lista,
            shell=False,
            check=True,
            capture_output=True,
            text=True
        )
        if mostrar_salida and resultado.stdout:
            print(resultado.stdout)
        return True
    except subprocess.CalledProcessError as e:
        # Silenciar errores esperados si es necesario
        if "iptables -D" in str(e):
             return False
        print(f"{RED}[!]{RESET} Error al ejecutar comando: {' '.join(comando_lista)}")
        if e.stderr:
            print(f"{RED}[!]{RESET} Detalles: {e.stderr}")
        return False

def crear_backup():
    """Crea un backup de las reglas actuales de iptables usando redirección en Python"""
    timestamp = datetime.now().strftime('%Y%n%d_%H%M%S')
    backup_file = f"iptables_backup_{timestamp}.rules"
    
    print(f"{YELLOW}[*]{RESET} Creando backup de reglas actuales...")
    try:
        with open(backup_file, "w", encoding="utf-8") as f:
            subprocess.run(["iptables-save"], stdout=f, check=True)
        print(f"{GREEN}[✓]{RESET} Backup creado: {backup_file}")
        log(f"Backup creado: {backup_file}")
        return backup_file
    except (subprocess.CalledProcessError, IOError) as e:
        print(f"{RED}[!]{RESET} Error al crear backup: {e}")
        return None

def mostrar_reglas():
    """Muestra las reglas actuales de iptables"""
    print(f"\n{BOLD}=== REGLAS ACTUALES DE IPTABLES ==={RESET}\n")
    ejecutar_comando(["iptables", "-L", "-n", "--line-numbers"])

def pausar():
    """Pausa para que el usuario pueda leer los resultados"""
    input(f"\n{BOLD}[Presiona ENTER para continuar...]{RESET}")

def proteger_syn_flood():
    """Protección contra ataques SYN flood"""
    print(f"\n{BOLD}=== PROTECCIÓN CONTRA SYN FLOOD ==={RESET}")
    print(f"{YELLOW}[*]{RESET} Esta protección limita las conexiones SYN a 5 por segundo")
    
    # Verificar si ya existe la regla usando lógica de Python
    resultado = subprocess.run(["iptables", "-L", "INPUT", "-n"], capture_output=True, text=True)
    if "tcp flags:0x17/0x02 limit: avg 5/sec burst 5" in resultado.stdout:
        print(f"{YELLOW}[!]{RESET} Esta protección ya está activa")
        pausar()
        return
    
    confirmar = input(f"{YELLOW}[?]{RESET} ¿Aplicar protección SYN flood? [S/n]: ").strip().lower()
    if confirmar in ['', 's', 'si', 'yes']:
        crear_backup()
        
        print(f"{YELLOW}[*]{RESET} Aplicando reglas...")
        if ejecutar_comando(["iptables", "-A", "INPUT", "-p", "tcp", "--syn", "-m", "limit", "--limit", "5/s", "-j", "ACCEPT"], False) and \
           ejecutar_comando(["iptables", "-A", "INPUT", "-p", "tcp", "--syn", "-j", "DROP"], False):
            print(f"{GREEN}[✓]{RESET} Protección contra SYN flood activada")
            log("Protección SYN flood activada")
            
            # Mostrar reglas aplicadas (filtrado en Python)
            print(f"\n{BOLD}Reglas aplicadas:{RESET}")
            res = subprocess.run(["iptables", "-L", "INPUT", "-n"], capture_output=True, text=True)
            for linea in res.stdout.split('\n'):
                 if "tcp flags:0x17/0x02" in linea:
                      print(linea)
        else:
            print(f"{RED}[!]{RESET} Error al aplicar reglas")
    
    pausar()

def limitar_acceso_ssh():
    """Limita el acceso SSH a IPs específicas"""
    print(f"\n{BOLD}=== LIMITAR ACCESO SSH ==={RESET}")
    print(f"{YELLOW}[!]{RESET} ADVERTENCIA: Esta acción puede dejarte sin acceso SSH")
    print(f"{YELLOW}[!]{RESET} Asegúrate de tener acceso físico o consola alternativa")
    
    confirmar = input(f"\n{YELLOW}[?]{RESET} ¿Continuar? [s/N]: ").strip().lower()
    if confirmar not in ['s', 'si', 'yes']:
        return
    
    # Obtener IP actual del usuario de forma segura
    print(f"\n{YELLOW}[*]{RESET} Detectando tu IP actual...")
    ssh_client = os.environ.get('SSH_CLIENT')
    if ssh_client:
        ip_actual = ssh_client.split()[0]
        print(f"{GREEN}[✓]{RESET} Tu IP actual: {ip_actual}")
    else:
        ip_actual = None
    
    # Solicitar IPs permitidas
    ips_permitidas = []
    while True:
        if ip_actual and not ips_permitidas:
            usar_actual = input(f"{YELLOW}[?]{RESET} ¿Usar tu IP actual ({ip_actual})? [S/n]: ").strip().lower()
            if usar_actual in ['', 's', 'si', 'yes']:
                ips_permitidas.append(ip_actual)
                print(f"{GREEN}[✓]{RESET} IP {ip_actual} agregada")
        
        ip = input(f"{BOLD}IP permitida (o Enter para finalizar): {RESET}").strip()
        
        if ip == "":
            break
        
        if validar_ip(ip):
            if ip not in ips_permitidas:
                ips_permitidas.append(ip)
                print(f"{GREEN}[✓]{RESET} IP {ip} agregada")
            else:
                print(f"{YELLOW}[!]{RESET} IP ya agregada")
        else:
            print(f"{RED}[!]{RESET} IP inválida")
    
    if not ips_permitidas:
        print(f"{RED}[!]{RESET} No se agregaron IPs. Operación cancelada")
        pausar()
        return
    
    # Mostrar resumen
    print(f"\n{BOLD}IPs que tendrán acceso SSH:{RESET}")
    for ip in ips_permitidas:
        print(f"  • {ip}")
    
    confirmar = input(f"\n{YELLOW}[?]{RESET} ¿Aplicar estas reglas? [s/N]: ").strip().lower()
    if confirmar in ['s', 'si', 'yes']:
        crear_backup()
        
        print(f"{YELLOW}[*]{RESET} Aplicando reglas SSH...")
        
        # Eliminar reglas SSH existentes (ignorar fallos si no existen)
        ejecutar_comando(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", "22", "-j", "DROP"], False)
        ejecutar_comando(["iptables", "-D", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT"], False)
        
        # Permitir IPs específicas
        for ip in ips_permitidas:
            if ejecutar_comando(f"iptables -A INPUT -p tcp --dport 22 -s {ip} -j ACCEPT", False):
                print(f"{GREEN}[✓]{RESET} Acceso SSH permitido desde {ip}")
                log(f"SSH permitido desde {ip}")
        
        # Bloquear todo lo demás
        if ejecutar_comando("iptables -A INPUT -p tcp --dport 22 -j DROP", False):
            print(f"{GREEN}[✓]{RESET} Acceso SSH bloqueado para otras IPs")
            log("SSH bloqueado para IPs no autorizadas")
        
        print(f"\n{GREEN}[✓]{RESET} Reglas SSH aplicadas correctamente")
        
        # Mostrar reglas
        print(f"\n{BOLD}Reglas SSH actuales:{RESET}")
        res = subprocess.run(["iptables", "-L", "INPUT", "-n", "--line-numbers"], capture_output=True, text=True)
        for linea in res.stdout.split('\n'):
             if ":22" in linea or " dpt:22" in linea:
                  print(linea)
    
    pausar()

def prevenir_ataques_dos():
    """Previene ataques DoS limitando conexiones HTTP"""
    print(f"\n{BOLD}=== PREVENCIÓN DE ATAQUES DOS ==={RESET}")
    print(f"{YELLOW}[*]{RESET} Limita conexiones simultáneas a puerto 80 (HTTP)")
    
    # Solicitar límites personalizados
    print(f"\n{BOLD}Configuración:{RESET}")
    print("• Límite de conexiones simultáneas por IP: 20 (recomendado)")
    print("• Límite de nuevas conexiones: 50/minuto")
    
    confirmar = input(f"\n{YELLOW}[?]{RESET} ¿Usar configuración recomendada? [S/n]: ").strip().lower()
    
    if confirmar in ['', 's', 'si', 'yes']:
        conn_limit = 20
        rate_limit = 50
    else:
        try:
            conn_limit = int(input("Conexiones simultáneas máximas: "))
            rate_limit = int(input("Nuevas conexiones por minuto: "))
        except ValueError:
            print(f"{RED}[!]{RESET} Valores inválidos")
            pausar()
            return
    
    crear_backup()
    
    print(f"\n{YELLOW}[*]{RESET} Aplicando reglas anti-DoS...")
    
    if ejecutar_comando(["iptables", "-A", "INPUT", "-p", "tcp", "--syn", "--dport", "80", "-m", "connlimit", "--connlimit-above", str(conn_limit), "-j", "DROP"], False) and \
       ejecutar_comando(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", "80", "-m", "limit", "--limit", f"{rate_limit}/minute", "--limit-burst", "30", "-j", "ACCEPT"], False):
        print(f"{GREEN}[✓]{RESET} Prevención de DoS activada")
        print(f"  • Máx. conexiones simultáneas: {conn_limit}")
        print(f"  • Máx. nuevas conexiones: {rate_limit}/minuto")
        log(f"Prevención DoS activada (conn_limit={conn_limit}, rate_limit={rate_limit})")
    else:
        print(f"{RED}[!]{RESET} Error al aplicar reglas")
    
    pausar()

def evitar_escaneo_de_puertos():
    """Protección contra escaneo de puertos"""
    print(f"\n{BOLD}=== PROTECCIÓN CONTRA ESCANEO DE PUERTOS ==={RESET}")
    print(f"{YELLOW}[*]{RESET} Detecta y bloquea paquetes típicos de escaneo")
    
    # Verificar si la cadena ya existe
    resultado = subprocess.run(["iptables", "-L", "SCANNER_PROTECTION", "-n"], capture_output=True)
    if resultado.returncode == 0:
        print(f"{YELLOW}[!]{RESET} La protección ya está configurada")
        opcion = input(f"{YELLOW}[?]{RESET} ¿Recrear la cadena? [s/N]: ").strip().lower()
        if opcion not in ['s', 'si', 'yes']:
            pausar()
            return
        # Eliminar cadena existente
        ejecutar_comando(["iptables", "-D", "INPUT", "-j", "SCANNER_PROTECTION"], False)
        ejecutar_comando(["iptables", "-F", "SCANNER_PROTECTION"], False)
        ejecutar_comando(["iptables", "-X", "SCANNER_PROTECTION"], False)
    
    crear_backup()
    
    print(f"\n{YELLOW}[*]{RESET} Creando cadena de protección...")
    
    if ejecutar_comando(["iptables", "-N", "SCANNER_PROTECTION"], False) and \
       ejecutar_comando(["iptables", "-A", "SCANNER_PROTECTION", "-p", "tcp", "--tcp-flags", "ALL", "NONE", "-j", "DROP"], False) and \
       ejecutar_comando(["iptables", "-A", "SCANNER_PROTECTION", "-p", "tcp", "--tcp-flags", "SYN,FIN", "SYN,FIN", "-j", "DROP"], False) and \
       ejecutar_comando(["iptables", "-A", "SCANNER_PROTECTION", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN,RST", "-j", "DROP"], False) and \
       ejecutar_comando(["iptables", "-A", "SCANNER_PROTECTION", "-p", "tcp", "--tcp-flags", "FIN,RST", "FIN,RST", "-j", "DROP"], False) and \
       ejecutar_comando(["iptables", "-A", "SCANNER_PROTECTION", "-p", "tcp", "--tcp-flags", "ALL", "SYN,RST,ACK,FIN,URG", "-j", "DROP"], False) and \
       ejecutar_comando(["iptables", "-A", "INPUT", "-j", "SCANNER_PROTECTION"], False):
        
        print(f"{GREEN}[✓]{RESET} Protección contra escaneo activada")
        print(f"\n{BOLD}Tipos de escaneo bloqueados:{RESET}")
        print("  • NULL scan (sin flags)")
        print("  • FIN scan")
        print("  • XMAS scan")
        print("  • SYN-RST combinados")
        log("Protección contra escaneo de puertos activada")
        
        # Mostrar reglas
        print(f"\n{BOLD}Reglas en SCANNER_PROTECTION:{RESET}")
        ejecutar_comando("iptables -L SCANNER_PROTECTION -n --line-numbers")
    else:
        print(f"{RED}[!]{RESET} Error al crear protección")
    
    pausar()

def bloquear_ip():
    """Bloquea una dirección IP específica"""
    print(f"\n{BOLD}=== BLOQUEAR DIRECCIÓN IP ==={RESET}")
    
    # Mostrar IPs actualmente bloqueadas (filtrado en Python)
    print(f"\n{YELLOW}[*]{RESET} Consultando IPs bloqueadas...")
    resultado = subprocess.run(["iptables", "-L", "INPUT", "-n"], capture_output=True, text=True)
    ips_bloqueadas = []
    for linea in resultado.stdout.split('\n'):
        if "DROP" in linea:
            partes = linea.split()
            if len(partes) >= 4 and partes[3] != '0.0.0.0/0':
                ips_bloqueadas.append(partes[3])
    
    if ips_bloqueadas:
        print(f"\n{BOLD}IPs actualmente bloqueadas:{RESET}")
        for ip in ips_bloqueadas:
            print(f"  • {ip}")
    
    # Solicitar IP a bloquear
    ip = input(f"\n{BOLD}Ingrese la IP a bloquear: {RESET}").strip()
    
    if not validar_ip(ip):
        print(f"{RED}[!]{RESET} Dirección IP inválida")
        pausar()
        return
    
    # Verificar si ya está bloqueada
    if ip in ips_bloqueadas:
        print(f"{YELLOW}[!]{RESET} Esta IP ya está bloqueada")
        pausar()
        return
    
    # Advertencia si es IP local
    if ip.startswith(('192.168.', '10.', '172.')):
        print(f"{YELLOW}[!]{RESET} ADVERTENCIA: Estás bloqueando una IP privada/local")
        confirmar = input(f"{YELLOW}[?]{RESET} ¿Continuar? [s/N]: ").strip().lower()
        if confirmar not in ['s', 'si', 'yes']:
            return
    
    # Solicitar motivo (opcional)
    motivo = input(f"{BOLD}Motivo del bloqueo (opcional): {RESET}").strip()
    
    crear_backup()
    
    print(f"\n{YELLOW}[*]{RESET} Bloqueando IP {ip}...")
    
    if ejecutar_comando(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], False):
        print(f"{GREEN}[✓]{RESET} IP {ip} bloqueada exitosamente")
        log_msg = f"IP {ip} bloqueada"
        if motivo:
            log_msg += f" - Motivo: {motivo}"
        log(log_msg)
        
        # Mostrar regla aplicada
        print(f"\n{BOLD}Regla aplicada:{RESET}")
        res = subprocess.run(["iptables", "-L", "INPUT", "-n", "--line-numbers"], capture_output=True, text=True)
        for linea in res.stdout.split('\n'):
             if ip in linea:
                  print(linea)
    else:
        print(f"{RED}[!]{RESET} Error al bloquear IP")
    
    pausar()

def desbloquear_ip():
    """Desbloquea una dirección IP"""
    print(f"\n{BOLD}=== DESBLOQUEAR DIRECCIÓN IP ==={RESET}")
    
    # Listar IPs bloqueadas (filtrado en Python)
    print(f"\n{YELLOW}[*]{RESET} Consultando reglas de bloqueo...")
    resultado = subprocess.run(["iptables", "-L", "INPUT", "-n", "--line-numbers"], capture_output=True, text=True)
    reglas_drop = [linea for linea in resultado.stdout.split('\n') if "DROP" in linea]
    
    if not reglas_drop:
        print(f"{YELLOW}[!]{RESET} No hay IPs bloqueadas actualmente")
        pausar()
        return
    
    print(f"\n{BOLD}Reglas de bloqueo actuales:{RESET}")
    for linea in reglas_drop:
        print(linea)
    
    # Solicitar IP o número de línea
    opcion = input(f"\n{BOLD}Ingrese IP o número de línea a desbloquear: {RESET}").strip()
    
    crear_backup()
    
    # Intentar como número de línea
    if opcion.isdigit():
        if ejecutar_comando(["iptables", "-D", "INPUT", opcion], False):
            print(f"{GREEN}[✓]{RESET} Regla eliminada")
            log(f"Regla de bloqueo #{opcion} eliminada")
        else:
            print(f"{RED}[!]{RESET} Error al eliminar regla")
    # Intentar como IP
    elif validar_ip(opcion):
        if ejecutar_comando(["iptables", "-D", "INPUT", "-s", opcion, "-j", "DROP"], False):
            print(f"{GREEN}[✓]{RESET} IP {opcion} desbloqueada")
            log(f"IP {opcion} desbloqueada")
        else:
            print(f"{RED}[!]{RESET} Error al desbloquear IP")
    else:
        print(f"{RED}[!]{RESET} Opción inválida")
    
    pausar()

def guardar_reglas():
    """Guarda las reglas actuales permanentemente"""
    print(f"\n{BOLD}=== GUARDAR REGLAS PERMANENTEMENTE ==={RESET}")
    print(f"{YELLOW}[*]{RESET} Las reglas actuales se guardarán y persistirán después de reiniciar")
    
    confirmar = input(f"\n{YELLOW}[?]{RESET} ¿Continuar? [S/n]: ").strip().lower()
    if confirmar not in ['', 's', 'si', 'yes']:
        return
    
    # Verificar si iptables-persistent está instalado (sin pipes)
    resultado = subprocess.run(["dpkg", "-l", "iptables-persistent"], capture_output=True)
    
    if resultado.returncode != 0:
        print(f"{YELLOW}[*]{RESET} iptables-persistent no está instalado")
        instalar = input(f"{YELLOW}[?]{RESET} ¿Instalar ahora? [S/n]: ").strip().lower()
        if instalar in ['', 's', 'si', 'yes']:
            print(f"{YELLOW}[*]{RESET} Instalando iptables-persistent...")
            env = os.environ.copy()
            env["DEBIAN_FRONTEND"] = "noninteractive"
            if ejecutar_comando(["apt-get", "install", "-y", "iptables-persistent"], False):
                print(f"{GREEN}[✓]{RESET} iptables-persistent instalado")
            else:
                print(f"{RED}[!]{RESET} Error al instalar")
                pausar()
                return
        else:
            pausar()
            return
    
    print(f"\n{YELLOW}[*]{RESET} Guardando reglas...")
    if ejecutar_comando(["netfilter-persistent", "save"], False):
        print(f"{GREEN}[✓]{RESET} Reglas guardadas en /etc/iptables/rules.v4")
        log("Reglas guardadas permanentemente")
    else:
        print(f"{RED}[!]{RESET} Error al guardar reglas")
    
    pausar()

def restaurar_backup():
    """Restaura un backup de reglas"""
    print(f"\n{BOLD}=== RESTAURAR BACKUP ==={RESET}")
    
    # Listar backups disponibles
    backups = [f for f in os.listdir('.') if f.startswith('iptables_backup_') and f.endswith('.rules')]
    
    if not backups:
        print(f"{YELLOW}[!]{RESET} No hay backups disponibles")
        pausar()
        return
    
    print(f"\n{BOLD}Backups disponibles:{RESET}")
    for i, backup in enumerate(backups, 1):
        # Extraer fecha del nombre
        fecha = backup.replace('iptables_backup_', '').replace('.rules', '')
        print(f"  [{i}] {backup} ({fecha})")
    
    try:
        opcion = int(input(f"\n{BOLD}Seleccione backup a restaurar (0 para cancelar): {RESET}"))
        if opcion == 0:
            return
        if 1 <= opcion <= len(backups):
            backup_seleccionado = backups[opcion - 1]
            
            print(f"\n{YELLOW}[!]{RESET} ADVERTENCIA: Esto reemplazará todas las reglas actuales")
            confirmar = input(f"{YELLOW}[?]{RESET} ¿Continuar? [s/N]: ").strip().lower()
            
            if confirmar in ['s', 'si', 'yes']:
                print(f"\n{YELLOW}[*]{RESET} Restaurando {backup_seleccionado}...")
                try:
                    with open(backup_seleccionado, "r", encoding="utf-8") as f:
                         subprocess.run(["iptables-restore"], stdin=f, check=True)
                    print(f"{GREEN}[✓]{RESET} Backup restaurado exitosamente")
                    log(f"Backup restaurado: {backup_seleccionado}")
                    mostrar_reglas()
                except subprocess.CalledProcessError as e:
                    print(f"{RED}[!]{RESET} Error al restaurar backup: {e}")
        else:
            print(f"{RED}[!]{RESET} Opción inválida")
    except ValueError:
        print(f"{RED}[!]{RESET} Entrada inválida")
    
    pausar()

def menu_principal():
    """Menú principal de la aplicación"""
    while True:
        limpiar_pantalla()
        banner()
        print(f"{BOLD}=== GESTOR DE IPTABLES ==={RESET}")
        print("")
        print("[1] Protección contra ataques SYN flood")
        print("[2] Limitar el acceso SSH")
        print("[3] Prevenir ataques DoS")
        print("[4] Evitar escaneo de puertos")
        print("[5] Bloquear IP")
        print("[6] Desbloquear IP")
        print("[7] Ver reglas actuales")
        print("[8] Guardar reglas permanentemente")
        print("[9] Restaurar backup")
        print("[10] Ver logs")
        print("[11] Salir")
        
        opcion = input(f"\n{BOLD}[+] Ingrese una opción: {RESET}").strip()
        
        if opcion == "1":
            proteger_syn_flood()
        elif opcion == "2":
            limitar_acceso_ssh()
        elif opcion == "3":
            prevenir_ataques_dos()
        elif opcion == "4":
            evitar_escaneo_de_puertos()
        elif opcion == "5":
            bloquear_ip()
        elif opcion == "6":
            desbloquear_ip()
        elif opcion == "7":
            mostrar_reglas()
            pausar()
        elif opcion == "8":
            guardar_reglas()
        elif opcion == "9":
            restaurar_backup()
        elif opcion == "10":
            if os.path.exists(LOG_FILE):
                print(f"\n{BOLD}=== ÚLTIMAS 30 LÍNEAS DEL LOG ==={RESET}\n")
                with open(LOG_FILE, "r", encoding="utf-8") as f:
                    lineas = f.readlines()
                    for linea in lineas[-30:]:
                        print(linea.strip())
            else:
                print(f"{YELLOW}[!]{RESET} No hay logs disponibles")
            pausar()
        elif opcion == "11":
            limpiar_pantalla()
            print(f"\n{GREEN}[✓]{RESET} ¡Gracias por usar Iptables Manager!\n")
            sys.exit(0)
        else:
            print(f"\n{RED}[!]{RESET} Opción no válida")
            pausar()

def main():
    """Función principal"""
    try:
        verificar_root()
        log("===== INICIO DE SESIÓN DE IPTABLES MANAGER =====")
        menu_principal()
    except KeyboardInterrupt:
        limpiar_pantalla()
        print(f"\n{YELLOW}[!]{RESET} Programa interrumpido por el usuario\n")
        sys.exit(0)

if __name__ == "__main__":
    main()