
from flask import Flask, request, jsonify
from flask_restful import Api, Resource
import toml
from models import db, Usuario, Proyecto, Sboom, Dependencia
from resources import UsuarioListResource, UsuarioResource, ProyectoListResource, ProyectoResource
from flask_cors import CORS
from flask_praetorian import Praetorian, auth_required, current_user
from datetime import timedelta, date
import os
import zipfile
import tempfile
from werkzeug.utils import secure_filename
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

from deepseek_dependency_extractor import DeepSeekDependencyExtractor
import asyncio

class ProyectoUploadResource(Resource):
    @auth_required
    def post(self, proyecto_id):
        """
        Endpoint para subir un .zip a un proyecto específico, extraer sus
        dependencias con IA y guardarlas en la base de datos.
        """
        user = current_user()

        # 1. Verificar proyecto
        proyecto = Proyecto.query.filter_by(id=proyecto_id, usuario_id=user.id).first()
        if not proyecto:
            return {'error': 'Proyecto no encontrado o no tienes permiso para acceder a él'}, 404

        # 2. Validar archivo
        if 'file' not in request.files or request.files['file'].filename == '':
            return {'error': 'No se seleccionó ningún archivo'}, 400

        file = request.files['file']
        if not file.filename.endswith('.zip'):
            return {'error': 'El archivo debe tener la extensión .zip'}, 400

        # 3. Procesar el ZIP
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                zip_path = os.path.join(temp_dir, secure_filename(file.filename))
                file.save(zip_path)

                extract_path = os.path.join(temp_dir, 'extracted')
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_path)

                # 4. Usar IA para extraer dependencias
                extractor = DeepSeekDependencyExtractor(api_token='cpk_145e465d6215459198b9895a7ffbf7b0.628389086c76508faebba4f6b0d1a90e.Aj37vjvBkJ3Dv79uyZe0BNCJcjR4F115')

                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                dependencias_extraidas = loop.run_until_complete(
                    extractor.extract_dependencies_from_directory(extract_path)
                )

                # 5. Guardar resultados
                sboom = Sboom(
                    nombre=f"SBOM de proyecto {proyecto.nombre}",
                    descripcion=f"SBOM generado automáticamente para el proyecto {proyecto.nombre}",
                    fecha=date.today(),
                    proyecto_id=proyecto.id
                )
                db.session.add(sboom)
                db.session.commit()

                for dep in dependencias_extraidas:
                    nombre = dep.get("name")
                    version = dep.get("version")
                    if nombre:
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
class ProyectoDependenciasResource(Resource):
    @auth_required
    def get(self, proyecto_id):
        from models import Sboom, Dependencia
        # Buscar el último SBOM asociado al proyecto
        sboom = Sboom.query.filter_by(proyecto_id=proyecto_id).order_by(Sboom.id.desc()).first()
        if not sboom:
            return {'error': 'No se encontró SBOM para este proyecto'}, 404
        dependencias = [d.to_dict() for d in sboom.dependencias]
        return {'proyecto_id': proyecto_id, 'sboom_id': sboom.id, 'dependencias': dependencias}, 200

class ProyectoDependenciaUpdateResource(Resource):
    @auth_required
    def put(self, proyecto_id, dependencia_id):
        from models import Sboom, Dependencia
        data = request.get_json()
        nueva_version = data.get('version')
        if not nueva_version:
            return {'error': 'Se requiere el campo "version"'}, 400
        # Buscar el último SBOM asociado al proyecto
        sboom = Sboom.query.filter_by(proyecto_id=proyecto_id).order_by(Sboom.id.desc()).first()
        if not sboom:
            return {'error': 'No se encontró SBOM para este proyecto'}, 404
        # Buscar la dependencia dentro del SBOM
        dependencia = Dependencia.query.filter_by(id=dependencia_id, sboom_id=sboom.id).first()
        if not dependencia:
            return {'error': 'No se encontró la dependencia para este proyecto'}, 404
        dependencia.version = nueva_version
        db.session.commit()
        return {'message': 'Versión actualizada', 'dependencia': dependencia.to_dict()}, 200

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
api.add_resource(ProyectoDependenciasResource, "/proyectos/<int:proyecto_id>/dependencias")
api.add_resource(ProyectoDependenciaUpdateResource, "/proyectos/<int:proyecto_id>/dependencias/<int:dependencia_id>")

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Solo en desarrollo
    app.run(host="0.0.0.0", port=5000, debug=True)

