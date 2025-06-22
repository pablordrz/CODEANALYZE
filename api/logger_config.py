import logging
import sys
import hashlib
import os
import re
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler
from flask import request

class SecureLogger:
    def __init__(self, log_file='app.log'):
        self.log_file = log_file
        self.last_hash = None
        self.logger = None
        self._initialize_secure_log()
        self._setup_logger()
    
    def _initialize_secure_log(self):
        """Inicializa el log seguro con una entrada inicial si es necesario."""
        try:
            if not os.path.exists(self.log_file) or os.path.getsize(self.log_file) == 0:
                self._create_initial_entry()
            else:
                self._read_last_hash()
        except Exception as e:
            print(f"⚠️ Error inicializando log seguro: {e}")
            self._create_initial_entry()

    def _create_initial_entry(self):
        """Crea la entrada inicial del registro seguro."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        # En la inicialización, no hay contexto de usuario, por lo que será 'system'
        user_id = self._get_user_id()
        
        initial_content = f"INIT_LOG | {user_id} | SYSTEM_START"
        initial_hash = self._calculate_hash(initial_content)
        
        entry = f"{timestamp}: | {user_id} | '{initial_hash}': Inicialización del registro seguro"
        
        with open(self.log_file, 'a', encoding='utf-8') as file:
            file.write(entry + '\n')
        
        self.last_hash = initial_hash

    def _read_last_hash(self):
        """Lee el último hash del archivo de log existente."""
        try:
            with open(self.log_file, 'r', encoding='utf-8') as file:
                lines = file.readlines()
            
            if lines:
                last_line = lines[-1].strip()
                hash_match = re.search(r"'([a-f0-9]{64})':", last_line)
                if hash_match:
                    self.last_hash = hash_match.group(1)
                else:
                    self._create_initial_entry()
            else:
                self._create_initial_entry()
        except Exception as e:
            print(f"⚠️ Error leyendo último hash: {e}")
            self._create_initial_entry()

    def _get_user_id(self) -> str:
        """
        Obtiene el email del usuario desde el contexto de la aplicación Flask.
        Si no hay contexto o usuario, devuelve 'system'.
        """
        if 'request' in globals() and request:
            try:
                from flask_praetorian import current_user
                user = current_user()
                if user and hasattr(user, 'email'):
                    return user.email
            except (ImportError, RuntimeError):
                pass
        return "system"

    def _calculate_hash(self, content: str, previous_hash: str = None) -> str:
        """Calcula el hash SHA-256 del contenido concatenado con el hash anterior."""
        to_hash = content + (previous_hash or '')
        return hashlib.sha256(to_hash.encode('utf-8')).hexdigest()

    def _setup_logger(self):
        """Configura el logger."""
        self.logger = logging.getLogger('secure_app_logger')
        self.logger.setLevel(logging.INFO)

        handler = TimedRotatingFileHandler(self.log_file, when='midnight', interval=1, backupCount=7, encoding='utf-8')
        handler.setLevel(logging.INFO)

        formatter = logging.Formatter('%(message)s')
        handler.setFormatter(formatter)

        if not self.logger.handlers:
            self.logger.addHandler(handler)
            stream_handler = logging.StreamHandler(sys.stdout)
            stream_handler.setFormatter(formatter)
            self.logger.addHandler(stream_handler)

        self.logger.propagate = False

    def log(self, level: str, message: str, **kwargs):
        """
        Registra un mensaje con hash de integridad y el nuevo formato.
        """
        try:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            user_id = self._get_user_id()
            
            entry_content = f"{timestamp} | {user_id} | {level.upper()} | {message}"
            current_hash = self._calculate_hash(entry_content, self.last_hash)
            
            secure_entry = f"{timestamp}: | {user_id} | '{current_hash}': {message}"
            
            log_func = getattr(self.logger, level.lower(), self.logger.info)
            log_func(secure_entry)
            
            self.last_hash = current_hash
            
        except Exception as e:
            error_msg = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | system | ERROR - Fallo en log seguro: {e}"
            if self.logger:
                self.logger.error(error_msg)

    def info(self, message: str, **kwargs):
        self.log('info', message, **kwargs)

    def warning(self, message: str, **kwargs):
        self.log('warning', message, **kwargs)

    def error(self, message: str, **kwargs):
        self.log('error', message, **kwargs)

    def debug(self, message: str, **kwargs):
        self.log('debug', message, **kwargs)

    def critical(self, message: str, **kwargs):
        self.log('critical', message, **kwargs)

# Crear instancia del logger
secure_logger = SecureLogger()

# Función para compatibilidad
def setup_logger():
    return secure_logger.logger

# Variable logger para compatibilidad con el código existente
logger = secure_logger 