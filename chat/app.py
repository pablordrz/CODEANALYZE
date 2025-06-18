from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import timedelta
import random
import requests
import toml
import jwt

app = Flask(__name__)
CORS(app)

# Cargar configuración desde archivo toml
app.config.from_file("config.toml", load=toml.load)

# Configuración de JWT
app.config['JWT_ACCESS_LIFESPAN'] = timedelta(hours=1)
app.config['JWT_REFRESH_LIFESPAN'] = timedelta(days=30)
app.config['JWT_SECRET_KEY'] = 'tu_clave_secreta_aqui'

# Lista de respuestas predefinidas
RESPUESTAS = [
    "¡Hola! ¿En qué puedo ayudarte?",
    "Entiendo tu pregunta. Déjame pensar...",
    "Esa es una buena pregunta.",
    "No estoy seguro de entender completamente. ¿Podrías reformularlo?",
    "Gracias por tu mensaje. ¿Hay algo más en lo que pueda ayudarte?",
    "Interesante punto de vista.",
    "Voy a investigar eso para ti.",
    "¿Podrías darme más detalles al respecto?",
    "Me alegro de que me hayas preguntado eso.",
    "Esa es una consulta muy común."
]

def verify_token(token):
    """
    Verifica el token con el servicio de autenticación
    """
    try:
        # Primero intentamos verificar el token localmente
        try:
            jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            return True
        except jwt.InvalidTokenError:
            pass

        # Si falla la verificación local, intentamos con el servicio de autenticación
        response = requests.get(
            'http://api:5000/auth',
            headers={'Authorization': f'Bearer {token}'}
        )
        return response.status_code == 200
    except Exception as e:
        print(f"Error verificando token: {str(e)}")
        return False

@app.route('/api/chat', methods=['POST'])
def chat():
    """
    Endpoint para procesar mensajes del chat.
    Requiere autenticación mediante token JWT.
    
    Formato de entrada:
    {
        "mensaje": "texto del mensaje"
    }
    
    Formato de salida:
    {
        "respuesta": "texto de la respuesta",
        "status": "success"
    }
    """
    # Verificar el token
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({
            'error': 'Token no proporcionado',
            'status': 'error'
        }), 401

    token = auth_header.split(' ')[1]
    if not verify_token(token):
        return jsonify({
            'error': 'Token inválido o expirado',
            'status': 'error'
        }), 401

    data = request.get_json()
    if not data or 'mensaje' not in data:
        return jsonify({
            'error': 'No se proporcionó un mensaje',
            'status': 'error'
        }), 400
    
    # Simplemente devolvemos una respuesta aleatoria de la lista
    respuesta = random.choice(RESPUESTAS)
    return jsonify({
        'respuesta': respuesta,
        'status': 'success'
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)
