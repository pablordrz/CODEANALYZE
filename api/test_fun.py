import requests
from datetime import datetime

# --- Configuración ---
BASE_URL = "http://localhost:5001"
TIMESTAMP = datetime.now().strftime("%Y%m%d%H%M%S")

USER_CREDS = {
    "username": f"testuser_{TIMESTAMP}", "password": "password123",
    "email": f"test_{TIMESTAMP}@example.com", "nombre": "Test User"
}

# --- Colores para la Salida ---
class bcolors:
    HEADER = '\033[95m'; OKGREEN = '\033[92m'; FAIL = '\033[91m'; ENDC = '\033[0m'
    BOLD = '\033[1m'; OKCYAN = '\033[96m'

# --- Almacenamiento de Estado Global ---
global_context = {
    "token": None,
    "project_id": None
}
test_results = []

# --- Funciones de Ayuda ---
def print_test_header(name):
    print(f"\n{bcolors.HEADER}===== {name} ====={bcolors.ENDC}")

def record_result(test_name, success, reason=""):
    """Registra y muestra el resultado de una prueba."""
    status = "PASS" if success else "FAIL"
    test_results.append({'name': test_name, 'status': status, 'reason': reason})
    if success:
        print(f"{bcolors.OKGREEN}[PASS]{bcolors.ENDC} {test_name.replace('_', ' ').title()}. {reason}")
    else:
        print(f"{bcolors.FAIL}[FAIL]{bcolors.ENDC} {test_name.replace('_', ' ').title()}: {reason}")

# --- Definición de los Tests ---

def test_01_user_registration():
    test_name = "User Registration"
    print_test_header(test_name)
    try:
        r = requests.post(f"{BASE_URL}/registro", json=USER_CREDS, timeout=5)
        if r.status_code == 201:
            record_result(test_name, True, "Usuario registrado exitosamente.")
            return True
        else:
            record_result(test_name, False, f"Se esperaba 201, se recibió {r.status_code}. Body: {r.text}")
            return False
    except requests.exceptions.RequestException as e:
        record_result(test_name, False, f"No se pudo conectar a la API. ¿Servidor en ejecución? ({e})")
        return False

def test_02_user_login():
    test_name = "User Login"
    print_test_header(test_name)
    try:
        login_data = {"username": USER_CREDS['username'], "password": USER_CREDS['password']}
        r = requests.post(f"{BASE_URL}/auth", json=login_data, timeout=5)
        if r.status_code == 200 and 'access_token' in r.json():
            global_context["token"] = r.json()['access_token']
            record_result(test_name, True, "Inicio de sesión exitoso y token obtenido.")
            return True
        else:
            record_result(test_name, False, f"Se esperaba 200, se recibió {r.status_code}. Body: {r.text}")
            return False
    except requests.exceptions.RequestException as e:
        record_result(test_name, False, f"No se pudo conectar a la API. ({e})")
        return False

def test_03_project_crud_cycle():
    test_name = "Project CRUD Cycle"
    print_test_header(test_name)
    if not global_context["token"]:
        record_result(test_name, False, "Omitido porque no hay token de autenticación.")
        return

    headers = {"Authorization": f"Bearer {global_context['token']}"}
    project_data = {
        "nombre": "Proyecto CRUD", "descripcion": "Descripción inicial.",
        "fecha": datetime.now().strftime("%Y-%m-%d"),
        "max_vulnerabilidades_permitidas": 20, "nivel_criticidad_maximo": "MEDIUM"
    }

    # 1. CREATE
    print(f"{bcolors.OKCYAN}INFO:{bcolors.ENDC} Probando CREACIÓN de proyecto...")
    r_create = requests.post(f"{BASE_URL}/proyectos", headers=headers, json=project_data)
    if r_create.status_code != 201:
        record_result(test_name, False, f"Fallo en CREATE: Se esperaba 201, se recibió {r_create.status_code}. Body: {r_create.text}")
        return
    global_context["project_id"] = r_create.json().get('id')
    print(f"{bcolors.OKCYAN}INFO:{bcolors.ENDC} Proyecto creado con ID: {global_context['project_id']}")

    # 2. READ
    print(f"{bcolors.OKCYAN}INFO:{bcolors.ENDC} Probando LECTURA de proyecto...")
    r_read = requests.get(f"{BASE_URL}/proyectos/{global_context['project_id']}", headers=headers)
    if r_read.status_code != 200:
        record_result(test_name, False, f"Fallo en READ: Se esperaba 200, se recibió {r_read.status_code}.")
        return

    # 3. UPDATE
    print(f"{bcolors.OKCYAN}INFO:{bcolors.ENDC} Probando ACTUALIZACIÓN de proyecto...")
    update_data = project_data.copy()
    update_data["nombre"] = "Proyecto CRUD Actualizado"
    r_update = requests.put(f"{BASE_URL}/proyectos/{global_context['project_id']}", headers=headers, json=update_data)
    if r_update.status_code != 200:
        record_result(test_name, False, f"Fallo en UPDATE: Se esperaba 200, se recibió {r_update.status_code}.")
        return
        
    # 4. DELETE
    print(f"{bcolors.OKCYAN}INFO:{bcolors.ENDC} Probando BORRADO de proyecto...")
    r_delete = requests.delete(f"{BASE_URL}/proyectos/{global_context['project_id']}", headers=headers)
    if r_delete.status_code != 200:
        record_result(test_name, False, f"Fallo en DELETE: Se esperaba 200, se recibió {r_delete.status_code}.")
        return

    # 5. VERIFY DELETION
    print(f"{bcolors.OKCYAN}INFO:{bcolors.ENDC} Verificando borrado...")
    r_verify = requests.get(f"{BASE_URL}/proyectos/{global_context['project_id']}", headers=headers)
    if r_verify.status_code != 404:
        record_result(test_name, False, f"Fallo en Verificación de Borrado: Se esperaba 404, se recibió {r_verify.status_code}.")
        return

    record_result(test_name, True, "El ciclo completo de Crear, Leer, Actualizar y Borrar funciona correctamente.")

# --- Ejecución de las Pruebas ---
if __name__ == "__main__":
    print(f"{bcolors.BOLD}Iniciando Suite de Pruebas Funcionales...{bcolors.ENDC}")

    if test_01_user_registration() and test_02_user_login():
        # Solo ejecutar el ciclo CRUD si el setup fue exitoso
        test_03_project_crud_cycle()

    # Resumen Final
    passed = len([r for r in test_results if r['status'] == 'PASS'])
    failed = len([r for r in test_results if r['status'] == 'FAIL'])

    print("\n" + "="*45)
    print(f"{bcolors.BOLD}Resumen de Pruebas Funcionales{bcolors.ENDC}")
    print(f"{bcolors.OKGREEN}Pruebas Pasadas: {passed}{bcolors.ENDC}")
    if failed > 0:
        print(f"{bcolors.FAIL}Pruebas Fallidas: {failed}{bcolors.ENDC}")
    print("="*45 + "\n")
    
    if failed == 0:
        print(f"{bcolors.OKGREEN}{bcolors.BOLD}¡FELICIDADES! Toda la suite de pruebas ha pasado. La API es funcional.{bcolors.ENDC}")
    else:
        print(f"{bcolors.FAIL}{bcolors.BOLD}Se encontraron fallos en la funcionalidad. Revisa los tests [FAIL].{bcolors.ENDC}")