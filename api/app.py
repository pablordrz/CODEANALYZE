from flask import Flask, request, jsonify
from flask_restful import Api, Resource
import toml
from models import db, Usuario
from resources import UsuarioListResource, UsuarioResource, ProyectoListResource, ProyectoResource
from flask_cors import CORS
from flask_praetorian import Praetorian, auth_required
from datetime import timedelta

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

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Solo en desarrollo
    app.run(host="0.0.0.0", port=5000, debug=True)

