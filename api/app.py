from flask import Flask, request, jsonify
from flask_restful import Api, Resource
import toml
from models import db, Usuario, Proyecto, Sboom, Dependencia
from resources import UsuarioListResource, UsuarioResource, ProyectoListResource, ProyectoResource
from flask_cors import CORS
from flask_praetorian import Praetorian, auth_required
from datetime import timedelta, date
import os
import zipfile
import tempfile
from werkzeug.utils import secure_filename
import json
import xml.etree.ElementTree as ET
import re

app = Flask(__name__)
app.config.from_file("./config.toml", load=toml.load)
CORS(app)  # Permitir CORS para todas las rutas

# Configuración de Praetorian
app.config['JWT_ACCESS_LIFESPAN'] = timedelta(hours=1)
app.config['JWT_REFRESH_LIFESPAN'] = timedelta(days=30)
app.config['JWT_SECRET_KEY'] = 'tu_clave_secreta_aqui'  # Debería ser la misma en todos los microservicios

db.init_app(app)
guard = Praetorian()
guard.init_app(app, Usuario)  # Inicializamos con el modelo Usuario
api = Api(app)

def find_python_dependencies(content):
    """Extrae dependencias de un archivo requirements.txt."""
    return [line for line in content.splitlines() if line and not line.startswith('#')]

def find_nodejs_dependencies(content):
    """Extrae dependencias de un archivo package.json."""
    dependencies = []
    try:
        data = json.loads(content)
        if 'dependencies' in data:
            dependencies.extend(data['dependencies'].keys())
        if 'devDependencies' in data:
            dependencies.extend(data['devDependencies'].keys())
    except json.JSONDecodeError:
        # El archivo puede estar malformado
        pass
    return dependencies

def find_maven_dependencies(content):
    """Extrae dependencias de un archivo pom.xml."""
    dependencies = []
    try:
        # Eliminar namespaces para simplificar la búsqueda
        content = re.sub(' xmlns="[^"]+"', '', content, count=1)
        root = ET.fromstring(content)
        for dep in root.findall('.//dependency'):
            groupId = dep.find('groupId')
            artifactId = dep.find('artifactId')
            if groupId is not None and artifactId is not None:
                dependencies.append(f"{groupId.text}:{artifactId.text}")
    except ET.ParseError:
        # El XML puede estar malformado
        pass
    return dependencies

class AuthResource(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        user = guard.authenticate(username, password)

        # Generar los tokens JWT
        access_token = guard.encode_jwt_token(user)
        refresh_token = guard.encode_jwt_token(user, is_refresh_token=True)

        # Devuelve los tokens en formato JSON
        return {
            'access_token': access_token,
            'refresh_token': refresh_token
}          , 200

    @auth_required
    def get(self):
        # Endpoint para verificar el token actual
        return jsonify({'message': 'Token válido'}) # Devuelve un mensaje JSON

class ProyectoUploadResource(Resource):
    @auth_required
    def post(self, proyecto_id):
        """
        Endpoint para subir un .zip a un proyecto específico, extraer sus
        dependencias y guardarlas en la base de datos actual.
        """
        from models import Proyecto, Sboom, Dependencia  # Importar modelos necesarios

        # 1. Verificar que el proyecto existe y pertenece al usuario autenticado
        proyecto = Proyecto.query.filter_by(id=proyecto_id, usuario_id=proyecto_id).first()
        if not proyecto:
            return {'error': 'Proyecto no encontrado o no tienes permiso para acceder a él'}, 404

        # 2. Validar el archivo
        if 'file' not in request.files or request.files['file'].filename == '':
            return {'error': 'No se seleccionó ningún archivo'}, 400
        
        file = request.files['file']
        if not file.filename.endswith('.zip'):
            return {'error': 'El archivo debe tener la extensión .zip'}, 400

        # 3. Procesar el archivo en un directorio temporal
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                zip_path = os.path.join(temp_dir, secure_filename(file.filename))
                file.save(zip_path)

                extract_path = os.path.join(temp_dir, 'extracted')
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_path)

                # 4. Recorrer archivos y buscar dependencias
                all_dependencies = []
                for root, _, files in os.walk(extract_path):
                    for filename in files:
                        try:
                            with open(os.path.join(root, filename), 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                            if filename == 'requirements.txt':
                                all_dependencies.extend(find_python_dependencies(content))
                            elif filename == 'package.json':
                                all_dependencies.extend(find_nodejs_dependencies(content))
                            elif filename == 'pom.xml':
                                all_dependencies.extend(find_maven_dependencies(content))
                        except Exception:
                            continue # Ignorar archivos no legibles

                # 5. Guardar dependencias en la base de datos en la tabla Sboom y Dependencia
                unique_dependencies = sorted(list(set(all_dependencies)))
                # Crear Sboom asociado al proyecto
                sboom = Sboom(
                    nombre=f"SBOM de proyecto {proyecto.nombre}",
                    descripcion=f"SBOM generado automáticamente para el proyecto {proyecto.nombre}",
                    fecha=date.today(),
                    proyecto_id=proyecto.id
                )
                db.session.add(sboom)
                db.session.commit()  # Para obtener el id del sboom

                # Crear Dependencia para cada dependencia extraída
                for dep in unique_dependencies:
                    # Si la dependencia tiene versión (por ejemplo, en requirements.txt: nombre==version)
                    if '==' in dep:
                        nombre, version = dep.split('==', 1)
                    elif ':' in dep:  # Para Maven
                        nombre, version = dep, None
                    else:
                        nombre, version = dep, None
                    dependencia = Dependencia(nombre=nombre, version=version, sboom_id=sboom.id)
                    db.session.add(dependencia)
                db.session.commit()

                return {
                    'message': f'Dependencias actualizadas para el proyecto "{proyecto.nombre}"',
                    'sboom': sboom.to_dict()
                }, 200

            except zipfile.BadZipFile:
                return {'error': 'El archivo proporcionado no es un ZIP válido.'}, 400
            except Exception as e:
                return {'error': f'Ocurrió un error interno durante el procesamiento: {str(e)}'}, 500

@app.route("/login", methods=["POST"])
def login():
    """
    Logs a user in by parsing a POST request containing user credentials and
    issuing a JWT token.
    """
    req = request.get_json(force=True)  # Usa 'request' en lugar de 'flask.request'
    username = req.get("username", None)
    password = req.get("password", None)
    
    # Aquí asumo que 'guard' es tu lógica de autenticación
    user = guard.authenticate(username, password)
    if user:
        ret = {"access_token": guard.encode_jwt_token(user)}
        return (jsonify(ret), 200)  # Usa 'jsonify' en lugar de 'flask.jsonify'
    else:
        return (jsonify({"error": "Invalid credentials"}), 401)  # Respuesta con error


api.add_resource(AuthResource, "/auth")
api.add_resource(UsuarioListResource, "/usuarios")
api.add_resource(UsuarioResource, "/usuarios/<int:id>")
api.add_resource(ProyectoListResource, "/proyectos")
api.add_resource(ProyectoResource, "/proyectos/<int:id>")
api.add_resource(ProyectoUploadResource, "/proyectos/<int:proyecto_id>/upload")

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Solo en desarrollo
    app.run(host="0.0.0.0", port=5000, debug=True)

