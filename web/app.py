import toml
from flask import Flask, render_template, flash, redirect, url_for, jsonify, request, session
from flask_praetorian import Praetorian, auth_required, roles_required, roles_accepted
from datetime import timedelta
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from functools import wraps
import base64, json

app = Flask(__name__, template_folder="templates")
app.config.from_file("config.toml", load=toml.load)



# Configuración de la API
API_URL = "http://localhost:5001"  # URL de la API
CHAT_URL = "http://localhost:5002"  # URL del servicio de chat

# Configuración de Praetorian
app.config['JWT_ACCESS_LIFESPAN'] = timedelta(hours=1)
app.config['JWT_REFRESH_LIFESPAN'] = timedelta(days=30)
app.config['JWT_SECRET_KEY'] = 'tu_clave_secreta_aqui'

db = SQLAlchemy()
guard = Praetorian()
db.init_app(app)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = session.get('access_token')
        if not token:
            flash("Por favor inicie sesión.", "error")
            return redirect(url_for('login'))
        
        try:
            # Verificar el token con la API
            response = requests.get(
                f"{API_URL}/auth",
                headers={'Authorization': f'Bearer {token}'}
            )
            
            if response.status_code != 200:
                # Intentar refrescar el token
                refresh_token = session.get('refresh_token')
                if refresh_token:
                    refresh_response = requests.post(
                        f"{API_URL}/auth/refresh",
                        headers={'Authorization': f'Bearer {refresh_token}'}
                    )
                    if refresh_response.status_code == 200:
                        data = refresh_response.json()
                        session['access_token'] = data['access_token']
                        return f(*args, **kwargs)
                
                session.clear()
                flash("Sesión expirada. Por favor inicie sesión nuevamente.", "error")
                return redirect(url_for('login'))
                
            return f(*args, **kwargs)
        except Exception as e:
            flash(f"Error de autenticación: {str(e)}", "error")
            return redirect(url_for('login'))
            
    return decorated

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = session.get('user')
            print("DEBUG usuario en sesión:", user)  # <-- Depuración
            if not user or user.get('rls') != role:
                flash("No tiene permisos para acceder a esta página.", "error")
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated
    return decorator

@app.route("/index.html")
@app.route("/")
def index():
    return render_template("layout.html", footer='footer.html', content='index.html', nav='nav.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        
        data = request.json 
        username = data.get('username')
        password = data.get('password')
        
        response = requests.post(
            f"{API_URL}/auth",
            json={
                "username": username,
                "password": password
            }
        )
        print(response.status_code)
        if response.status_code == 200:
            token = response.json()['access_token']
            flash('Login exitoso', 'success')
            flash('Token: ' + token, 'info')
            session['access_token'] = token
            # Decodificar el token y guardar los datos del usuario en la sesión
            payload = token.split('.')[1]
            # Añadir padding si es necesario
            padding = '=' * (-len(payload) % 4)
            payload += padding
            decoded = base64.urlsafe_b64decode(payload)
            user_data = json.loads(decoded)
            session['user'] = user_data
            return redirect(url_for('proyecto'))
        else:
            flash('Credenciales inválidas', 'error')
    
    # Si es GET, mostrar la página de login
    return render_template("layout.html", content="login.html", footer='footer.html', nav='nav.html')

@app.route('/registro', methods=['GET'])
def registro():
    return render_template("layout.html", content="registro.html", footer='footer.html', nav='nav.html')

@app.route("/logout")
def logout():
    # Limpiar la sesión
    session.clear()
    flash("Sesión cerrada con éxito.", "exito")
    return redirect(url_for("index"))

@app.route("/chat")
@app.route("/chat/<int:id>")
def proyecto(id=None):
    if id is None:
        return render_template("layout.html", content="chat.html", footer='footer.html', nav='nav.html')
    return render_template("layout.html", content="chat.html", footer='footer.html', nav='nav.html', chat_seleccionado=id)

@app.route("/anadir")
def anadir():
    return render_template("layout.html", footer='footer.html', content='proyecto_nuevo.html', nav='nav.html')

@app.route("/proyecto/editar/<int:id>", methods=["GET"])
def proyecto_editar(id):
    proyecto = {'id': id}
    return render_template("layout.html", footer='footer.html', content='proyecto_editar.html', nav='nav.html', proyecto=proyecto)

@app.route("/usuarios")
def usuarios():
    return render_template("layout.html", footer='footer.html', content='usuarios.html', nav='nav.html')

@app.route("/usuario/nuevo", methods=["GET"])
@role_required('admin')
def usuario_nuevo():
    return render_template("layout.html", footer='footer.html', content='usuario_nuevo.html', nav='nav.html')

@app.route("/usuario/editar/<int:id>", methods=["GET"])
@role_required('admin')
def usuario_editar(id=None):
    usuario = {'id': id}
    return render_template("layout.html", footer='footer.html', content='usuario_editar.html', nav='nav.html', usuario=usuario)

def send_chat_message(mensaje):
    """
    Envía un mensaje al servicio de chat
    """
    token = session.get('access_token')
    if not token:
        return {'error': 'No hay sesión activa'}, 401

    try:
        response = requests.post(
            f"{CHAT_URL}/api/chat",
            json={'mensaje': mensaje},
            headers={'Authorization': f'Bearer {token}'}
        )
        return response.json(), response.status_code
    except Exception as e:
        return {'error': f'Error al conectar con el servicio de chat: {str(e)}'}, 500

@app.route("/api/chat", methods=["POST"])
@token_required
def chat_api():
    """
    Endpoint para enviar mensajes al chat
    """
    data = request.get_json()
    if not data or 'mensaje' not in data:
        return jsonify({'error': 'No se proporcionó un mensaje'}), 400

    response, status_code = send_chat_message(data['mensaje'])
    return jsonify(response), status_code


@app.route("/sync-session", methods=["POST"])
def sync_session():
    data = request.get_json()
    token = data.get("access_token")
    if not token:
        return jsonify({"error": "No token provided"}), 400
    try:
        payload = token.split('.')[1]
        padding = '=' * (-len(payload) % 4)
        payload += padding
        decoded = base64.urlsafe_b64decode(payload)
        user_data = json.loads(decoded)
        session['user'] = user_data
        session['access_token'] = token
        return jsonify({"message": "Session synchronized"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400
    

@app.route("/buscar")
def buscar():
    q = request.args.get('q')
    return render_template("layout.html", footer='footer.html', content='buscar.html', nav='nav.html', q=q)

@app.route("/proyecto/<int:proyecto_id>/versiones", methods=["GET"])
def dependencias_version(proyecto_id):
    return render_template("layout.html", footer='footer.html', content='dependencias_version.html', nav='nav.html', proyecto_id=proyecto_id)

