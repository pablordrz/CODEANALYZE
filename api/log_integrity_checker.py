#!/usr/bin/env python3
"""
Script para verificar la integridad de los logs usando el sistema de hash SHA-256 encadenado
"""

import hashlib
import re
import os
from datetime import datetime

class LogIntegrityChecker:
    def __init__(self, log_file='app.log'):
        self.log_file = log_file
    
    def _calculate_hash(self, content: str, previous_hash: str = None) -> str:
        """Calcula el hash SHA-256 del contenido concatenado con el hash anterior"""
        if previous_hash:
            to_hash = content + previous_hash
        else:
            to_hash = content
        return hashlib.sha256(to_hash.encode('utf-8')).hexdigest()
    
    def verify_integrity(self) -> bool:
        """Verifica la integridad de la cadena de logs"""
        try:
            if not os.path.exists(self.log_file):
                print(f"❌ El archivo de log '{self.log_file}' no existe")
                return False
            
            with open(self.log_file, 'r', encoding='utf-8') as file:
                lines = [line.strip() for line in file.readlines() if line.strip()]
            
            if not lines:
                print("✅ El archivo de log está vacío (no hay entradas para verificar)")
                return True
            
            print(f"🔍 Verificando integridad de {len(lines)} entradas en '{self.log_file}'...")
            
            previous_hash = None
            
            for i, line in enumerate(lines):
                # Extraer hash almacenado
                hash_match = re.search(r"'([a-f0-9]{64})':", line)
                if not hash_match:
                    print(f"❌ Línea {i+1}: No se pudo extraer el hash")
                    return False
                
                stored_hash = hash_match.group(1)
                
                # Extraer componentes para recalcular hash
                timestamp_match = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}):', line)
                user_match = re.search(r'\| ([^|]+) \|', line)
                content_match = re.search(r"': (.+)$", line)
                
                if not (timestamp_match and user_match and content_match):
                    print(f"❌ Línea {i+1}: Formato de línea inválido")
                    return False
                
                timestamp = timestamp_match.group(1)
                user_id = user_match.group(1).strip()
                content = content_match.group(1)
                
                # Recalcular hash esperado
                if i == 0:
                    # Primera entrada (inicialización)
                    entry_content = f"INIT_LOG | {user_id} | SYSTEM_START"
                    expected_hash = self._calculate_hash(entry_content)
                else:
                    # Entradas regulares
                    entry_content = f"{timestamp} | {user_id} | INFO | {content}"
                    expected_hash = self._calculate_hash(entry_content, previous_hash)
                
                if stored_hash != expected_hash:
                    print(f"❌ Línea {i+1}: Hash no coincide")
                    print(f"   Hash almacenado: {stored_hash}")
                    print(f"   Hash esperado:   {expected_hash}")
                    return False
                
                previous_hash = stored_hash
                print(f"✅ Línea {i+1}: Hash verificado correctamente")
            
            print("🎉 ¡Todas las entradas verificadas! La integridad del log está intacta.")
            return True
            
        except Exception as e:
            print(f"❌ Error durante la verificación: {e}")
            return False
    
    def show_log_summary(self):
        """Muestra un resumen del archivo de log"""
        try:
            if not os.path.exists(self.log_file):
                print(f"❌ El archivo de log '{self.log_file}' no existe")
                return
            
            with open(self.log_file, 'r', encoding='utf-8') as file:
                lines = file.readlines()
            
            print(f"📊 Resumen del archivo de log '{self.log_file}':")
            print(f"   - Total de líneas: {len(lines)}")
            print(f"   - Tamaño del archivo: {os.path.getsize(self.log_file)} bytes")
            print(f"   - Última modificación: {datetime.fromtimestamp(os.path.getmtime(self.log_file))}")
            
            if lines:
                print(f"   - Primera entrada: {lines[0].strip()}")
                print(f"   - Última entrada: {lines[-1].strip()}")
            
        except Exception as e:
            print(f"❌ Error al mostrar resumen: {e}")

def main():
    """Función principal para ejecutar la verificación"""
    checker = LogIntegrityChecker()
    
    print("🔐 Verificador de Integridad de Logs")
    print("=" * 50)
    
    # Mostrar resumen
    checker.show_log_summary()
    print()
    
    # Verificar integridad
    if checker.verify_integrity():
        print("\n✅ RESULTADO: Los logs mantienen su integridad")
    else:
        print("\n❌ RESULTADO: Se detectó posible manipulación en los logs")

if __name__ == "__main__":
    main() 