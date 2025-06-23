# -*- coding: utf-8 -*-
from flask import Flask, request, jsonify, Response
from flask_restful import Api, Resource
import toml
from models import db, Usuario, Proyecto, Sboom, Dependencia, Vulnerabilidad
from resources import UsuarioListResource, UsuarioResource, ProyectoListResource, ProyectoResource, RegistroPublicoResource
from flask_cors import CORS
from flask_praetorian import Praetorian, auth_required, current_user
from datetime import timedelta, date
import os
import zipfile
import tempfile
from werkzeug.utils import secure_filename
import re
from logger_config import logger

import uuid
import json
from datetime import datetime, timezone

# --- Nuevas importaciones ---
from filtrado import StaticDependencyAnalyzer # Importamos la nueva clase
from deepseek_dependency_extractor import DeepSeekDependencyExtractor
import asyncio
from gemini import GeminiDependencyAnalyzer
from vulnerability_scanner import BuscadorCVE

app = Flask(__name__)
app.config.from_file("./config.toml", load=toml.load)
CORS(app)

app.config['JWT_ACCESS_LIFESPAN'] = timedelta(hours=1)
app.config['JWT_REFRESH_LIFESPAN'] = timedelta(days=30)
app.config['JWT_SECRET_KEY'] = 'tu_clave_secreta_aqui'

db.init_app(app)
guard = Praetorian()
guard.init_app(app, Usuario)
api = Api(app)

# --- Mapeo de extensiones a lenguajes ---
ext_to_lang = {
    '.py': 'Python',
    '.js': 'JavaScript',
    '.java': 'Java',
    '.c': 'C',
    '.cpp': 'C++',
    '.cs': 'C#',
    '.rb': 'Ruby',
    '.php': 'PHP',
    '.go': 'Go',
    '.rs': 'Rust',
    '.ts': 'TypeScript',
    '.tsx': 'TypeScript',
    '.m': 'Objective-C',
    '.swift': 'Swift',
    '.kt': 'Kotlin',
    '.scala': 'Scala',
    '.h': 'C/C++ Header',
    '.hpp': 'C++ Header',
    '.json': 'JSON',
    '.xml': 'XML',
    '.yml': 'YAML',
    '.yaml': 'YAML',
    '.toml': 'TOML',
    '.gradle': 'Gradle',
    '.pom': 'Maven',
    '.txt': 'Texto',
}

def get_tipo_archivo(archivo_origen):
    if not archivo_origen:
        return None
    _, ext = os.path.splitext(archivo_origen)
    return ext_to_lang.get(ext.lower(), ext.lower().replace('.', '').upper() if ext else None)

class AuthResource(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        user = guard.authenticate(username, password)
        logger.info(f"Usuario '{username}' ha iniciado sesión exitosamente.")
        access_token = guard.encode_jwt_token(user)
        refresh_token = guard.encode_jwt_token(user, is_refresh_token=True)
        return {'access_token': access_token, 'refresh_token': refresh_token}, 200

    @auth_required
    def get(self):
        return jsonify({'message': 'Token válido'})

class ProyectoUploadResource(Resource):
    @auth_required
    def post(self, proyecto_id):
        user = current_user()
        proyecto = Proyecto.query.filter_by(id=proyecto_id, usuario_id=user.id).first()
        if not proyecto:
            return {'error': 'Proyecto no encontrado o no tienes permiso'}, 404

        if 'file' not in request.files or not request.files['file'].filename:
            return {'error': 'No se seleccionó ningún archivo'}, 400

        file = request.files['file']
        if not file.filename.endswith('.zip'):
            return {'error': 'El archivo debe ser .zip'}, 400

        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                zip_path = os.path.join(temp_dir, secure_filename(file.filename))
                file.save(zip_path)

                extract_path = os.path.join(temp_dir, 'extracted')
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_path)

                # --- LÓGICA DE EXTRACCIÓN TOTALMENTE NUEVA CON GEMINI ---
                
                print("--- Iniciando análisis de dependencias con Gemini ---")
                
                api_key = app.config.get('GEMINI_API_KEY')
                if not api_key:
                    raise ValueError("La variable de entorno GEMINI_API_KEY no está configurada.")
                
                # 1. Analizar todo el proyecto extraído
                analyzer = GeminiDependencyAnalyzer(api_key=api_key)
                final_dependencies = asyncio.run(analyzer.analyze_project(extract_path))

                # 2. Limpiar SBOMs anteriores y guardar los nuevos resultados
                print("--- Guardando resultados en la Base de Datos ---")
                
                sbooms_antiguos = Sboom.query.filter_by(proyecto_id=proyecto.id).all()
                for sboom_viejo in sbooms_antiguos:
                    db.session.delete(sboom_viejo)
                db.session.commit()

                sboom = Sboom(
                    nombre=f"{proyecto.nombre}",
                    descripcion=f"{proyecto.nombre}",
                    fecha=date.today(),
                    proyecto_id=proyecto.id
                )
                db.session.add(sboom)
                db.session.flush()

                for dep in final_dependencies:
                    nombre = dep.get("name")
                    if nombre:
                        dependencia = Dependencia(
                            nombre=nombre,
                            version=dep.get("version"),
                            archivo_origen=dep.get("archivo_origen"),
                            sboom_id=sboom.id
                        )
                        db.session.add(dependencia)

                db.session.commit()

                return {
                    'message': f'Análisis con Gemini completado. Dependencias actualizadas para "{proyecto.nombre}"',
                    'sboom': sboom.to_dict(),
                    'dependencias_encontradas': len(final_dependencies)
                }, 200

            except zipfile.BadZipFile:
                return {'error': 'El archivo proporcionado no es un ZIP válido.'}, 400
            except Exception as e:
                error_msg = f'Ocurrió un error interno: {str(e)}'
                print(error_msg)
                import traceback
                traceback.print_exc()
                db.session.rollback()
                return {'error': error_msg}, 500
  

class ProyectoDependenciasResource(Resource):
    @auth_required
    def get(self, proyecto_id):
        user = current_user()
        
        # Verificar si el usuario es admin
        user_role = None
        if hasattr(user, 'roles'):
            if isinstance(user.roles, str):
                user_role = user.roles.split(',')[0]
            else:
                user_role = user.roles
        elif hasattr(user, 'rolenames'):
            user_role = user.rolenames[0] if user.rolenames else None
        
        # Buscar el proyecto
        proyecto = Proyecto.query.get_or_404(proyecto_id)
        
        # Verificar permisos: solo el propietario o admin puede ver las dependencias
        if user_role != 'admin' and proyecto.usuario_id != user.id:
            return {'error': 'No tienes permisos para ver las dependencias de este proyecto'}, 403
        
        # Buscar el SBOM del proyecto
        sboom = Sboom.query.filter_by(proyecto_id=proyecto_id).order_by(Sboom.id.desc()).first()
        if not sboom:
            return {'error': 'No se encontró SBOM para este proyecto'}, 404
        
        dependencias = [d.to_dict() for d in sboom.dependencias]
        return {'proyecto_id': proyecto_id, 'sboom_id': sboom.id, 'dependencias': dependencias,'supera_aceptabilidad': verifica_aceptabilidad(proyecto)}, 200

class VulnerabilityScanResource(Resource):
    @auth_required
    def post(self, sboom_id):
        """
        Realiza un análisis de vulnerabilidades para todas las dependencias de un SBOM.
        """
        from models import db, Sboom, Vulnerabilidad
        
        try:
            # Obtener el SBOM
            sboom = Sboom.query.get_or_404(sboom_id)
            
            # Verificar permisos
            if sboom.proyecto.usuario_id != current_user().id:
                return {'error': 'No tienes permiso para analizar este SBOM'}, 403
            
            # Obtener la API key de NVD
            nvd_api_key = app.config.get('NVD_API_KEY')
            
            # Obtener la API key de Gemini
            gemini_api_key = app.config.get('GEMINI_API_KEY')
            
            # Inicializar buscador
            buscador = BuscadorCVE(nvd_api_key=nvd_api_key, gemini_api_key=gemini_api_key)
            
            nuevas_vulnerabilidades_count = 0
            dependencias_procesadas = 0
            errores = []
            
            
            # Procesar cada dependencia del SBOM
            for dep in sboom.dependencias:
                dependencias_procesadas += 1
                
                try:
                    # Limpiar vulnerabilidades antiguas para esta dependencia
                    Vulnerabilidad.query.filter_by(dependencia_id=dep.id).delete()
                    
                    # Buscar vulnerabilidades para esta dependencia
                    tipo_archivo = get_tipo_archivo(getattr(dep, 'archivo_origen', None))
                    vulnerabilidades_halladas = buscador.buscar_vulnerabilidades_para_dependencia(
                        dep.nombre, dep.version, tipo_archivo
                    )
                    
                    # Guardar vulnerabilidades en la base de datos
                    for vuln_data in vulnerabilidades_halladas:
                        # Verificar si ya existe esta vulnerabilidad para esta dependencia
                        existe = Vulnerabilidad.query.filter_by(
                            cve_id=vuln_data['cve_id'], 
                            dependencia_id=dep.id
                        ).first()
                        
                        if not existe:
                            # Crear nueva vulnerabilidad
                            nueva_vuln = Vulnerabilidad(
                                dependencia_id=dep.id,
                                cve_id=vuln_data['cve_id'],
                                descripcion=vuln_data['descripcion'],
                                puntuacion_cvss=vuln_data['puntuacion_cvss'],
                                severidad=vuln_data['severidad']
                            )
                            db.session.add(nueva_vuln)
                            nuevas_vulnerabilidades_count += 1
                            
                            
                    
                except Exception as e:
                    error_msg = f"Error procesando dependencia {dep.nombre}: {str(e)}"
                    errores.append(error_msg)
                    continue
            
            # Confirmar cambios en la base de datos
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                return {
                    'error': 'Error guardando vulnerabilidades en la base de datos',
                    'details': str(e)
                }, 500
            
            # Preparar respuesta
            respuesta = {
                'message': 'Análisis de vulnerabilidades completado para todas las dependencias.',
                'sboom_id': sboom_id,
                'sboom_nombre': sboom.nombre,
                'nuevas_vulnerabilidades_encontradas': nuevas_vulnerabilidades_count,
                'dependencias_procesadas': dependencias_procesadas,
                'total_dependencias': len(sboom.dependencias)
            }
            
            if errores:
                respuesta['errores'] = errores
                respuesta['warning'] = f'Se encontraron {len(errores)} errores durante el procesamiento'
            
            return respuesta, 200
            
        except Exception as e:
            return {
                'error': 'Error interno durante el análisis de vulnerabilidades',
                'details': str(e)
            }, 500


class VulnerabilityScanSingleResource(Resource):
    @auth_required
    def post(self, dependencia_id):
        """
        Realiza un análisis de vulnerabilidades para una dependencia específica.
        """
        from models import db, Dependencia, Vulnerabilidad
        
        try:
            # Obtener la dependencia
            dependencia = Dependencia.query.get_or_404(dependencia_id)
            
            # Verificar permisos
            if dependencia.sboom.proyecto.usuario_id != current_user().id:
                return {'error': 'No tienes permiso para analizar esta dependencia'}, 403
            
            # Limpiar vulnerabilidades antiguas para esta dependencia
            Vulnerabilidad.query.filter_by(dependencia_id=dependencia.id).delete()
            
            # Obtener la API key de NVD
            nvd_api_key = app.config.get('NVD_API_KEY')
            
            # Obtener la API key de Gemini
            gemini_api_key = app.config.get('GEMINI_API_KEY')
            
            # Inicializar buscador
            buscador = BuscadorCVE(nvd_api_key=nvd_api_key, gemini_api_key=gemini_api_key)
            
            
            # Buscar vulnerabilidades
            tipo_archivo = get_tipo_archivo(getattr(dependencia, 'archivo_origen', None))
            vulnerabilidades_halladas = buscador.buscar_vulnerabilidades_para_dependencia(
                dependencia.nombre, dependencia.version, tipo_archivo
            )
            
            nuevas_vulnerabilidades_count = 0
            
            # Guardar vulnerabilidades
            for vuln_data in vulnerabilidades_halladas:
                existe = Vulnerabilidad.query.filter_by(
                    cve_id=vuln_data['cve_id'], 
                    dependencia_id=dependencia.id
                ).first()
                
                if not existe:
                    nueva_vuln = Vulnerabilidad(
                        dependencia_id=dependencia.id,
                        cve_id=vuln_data['cve_id'],
                        descripcion=vuln_data['descripcion'],
                        puntuacion_cvss=vuln_data['puntuacion_cvss'],
                        severidad=vuln_data['severidad']
                    )
                    db.session.add(nueva_vuln)
                    nuevas_vulnerabilidades_count += 1
            
            db.session.commit()
            
            return {
                'message': f'Análisis completado para {dependencia.nombre}',
                'dependencia': dependencia.nombre,
                'version': dependencia.version,
                'nuevas_vulnerabilidades_encontradas': nuevas_vulnerabilidades_count,
                'total_vulnerabilidades_encontradas': len(vulnerabilidades_halladas)
            }, 200
            
        except Exception as e:
            return {
                'error': 'Error durante el análisis de la dependencia',
                'details': str(e)
            }, 500
            
            
def verifica_aceptabilidad(proyecto):
    max_vuln = proyecto.max_vulnerabilidades_permitidas
    nivel_maximo = (proyecto.nivel_criticidad_maximo or '').upper()

    severidades = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    nivel_max_num = severidades.get(nivel_maximo, 4)  # Por defecto CRITICAL

    total_vulnerabilidades = 0
    mayor_severidad_num = 0

    if not proyecto or not getattr(proyecto, 'sbooms', None):
        return False

    for sboom in proyecto.sbooms or []:
        if not getattr(sboom, 'dependencias', None):
            continue
        for dep in sboom.dependencias or []:
            if not getattr(dep, 'vulnerabilidades', None):
                continue
            for v in dep.vulnerabilidades or []:
                total_vulnerabilidades += 1
                sev_num = severidades.get((v.severidad or '').upper(), 0)
                if sev_num > mayor_severidad_num:
                    mayor_severidad_num = sev_num

    supera_vuln = max_vuln is not None and total_vulnerabilidades > max_vuln
    supera_severidad = mayor_severidad_num > nivel_max_num

    return supera_vuln or supera_severidad

class ProyectoDependenciaUpdateResource(Resource):
    @auth_required
    def put(self, proyecto_id, dependencia_id):
        data = request.get_json()
        nueva_version = data.get('version')
        if not nueva_version:
            return {'error': 'Se requiere el campo "version"'}, 400
        sboom = Sboom.query.filter_by(proyecto_id=proyecto_id).order_by(Sboom.id.desc()).first()
        if not sboom:
            return {'error': 'No se encontró SBOM para este proyecto'}, 404
        dependencia = Dependencia.query.filter_by(id=dependencia_id, sboom_id=sboom.id).first()
        if not dependencia:
            return {'error': 'No se encontró la dependencia para este proyecto'}, 404
        dependencia.version = nueva_version
        db.session.commit()
        logger.info(f"Usuario '{current_user().username}' actualizó la versión de la dependencia ID: {dependencia_id} a '{nueva_version}' en el proyecto ID: {proyecto_id}.")
        return {'message': 'Versión actualizada', 'dependencia': dependencia.to_dict()}, 200
    

class SbomGenerateResource(Resource):
    @auth_required
    def get(self, proyecto_id):
        """
        Genera un SBOM (Software Bill of Materials) en formato CycloneDX JSON 
        y lo devuelve como un archivo descargable (sbom.json).
        """
        user = current_user()
        
        # --- 1. Buscar el proyecto y verificar permisos ---
        proyecto = Proyecto.query.get_or_404(proyecto_id)
        
        if proyecto.usuario_id != user.id:
            logger.warning(f"Intento no autorizado de generar SBOM para el proyecto ID {proyecto_id} por el usuario '{user.username}'.")
            return {'error': 'No tienes permisos para generar un SBOM para este proyecto'}, 403
            
        # --- 2. Obtener el SBOM más reciente del proyecto ---
        sboom = Sboom.query.filter_by(proyecto_id=proyecto.id).order_by(Sboom.fecha.desc(), Sboom.id.desc()).first()
        
        if not sboom:
            logger.info(f"No se encontró SBOM para el proyecto ID {proyecto_id} al intentar generar el archivo.")
            return {'error': 'No se encontró un SBOM para este proyecto. Sube y analiza el proyecto primero.'}, 404
            
        # --- 3. Construir el SBOM en formato CycloneDX v1.4 ---
        
        components = []
        for dep in sboom.dependencias:
            purl = f"pkg:generic/{dep.nombre}@{dep.version}" if dep.version else f"pkg:generic/{dep.nombre}"
            
            component_data = {
                "type": "library",
                "name": dep.nombre,
                "version": dep.version or "N/A",
                "purl": purl
            }
            
            # Añadir información del archivo de origen si está disponible
            if dep.archivo_origen and dep.archivo_origen != "N/A":
                component_data["properties"] = [
                    {
                        "name": "source_file",
                        "value": dep.archivo_origen
                    }
                ]
            
            components.append(component_data)

        sbom_data = {
            "$schema": "http://cyclonedx.org/schema/bom-1.4.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "component": {
                    "type": "application",
                    "name": proyecto.nombre,
                    "version": "1.0.0",
                    "description": proyecto.descripcion
                }
            },
            "components": components
        }
        
        logger.info(f"Se generó exitosamente el SBOM en formato CycloneDX para el proyecto ID {proyecto_id} (SBOM ID: {sboom.id}).")
        
        # --- 4. Crear y devolver una respuesta de archivo descargable ---
        
        # Convertir el diccionario a una cadena de texto JSON
        sbom_json_string = json.dumps(sbom_data, indent=4)
        
        # Crear la respuesta de Flask
        response = Response(sbom_json_string, mimetype='application/json')
        
        # Establecer la cabecera para forzar la descarga con el nombre 'sbom.json'
        response.headers['Content-Disposition'] = 'attachment; filename=sbom.json'
        
        return response




@app.route("/login", methods=["POST"])
def login():
    req = request.get_json(force=True)
    username = req.get("username", None)
    password = req.get("password", None)
    user = guard.authenticate(username, password)
    if user:
        logger.info(f"Usuario '{username}' ha iniciado sesión exitosamente (ruta /login).")
        ret = {"access_token": guard.encode_jwt_token(user)}
        return jsonify(ret), 200
    else:
        return jsonify({"error": "Invalid credentials"}), 401

api.add_resource(AuthResource, "/auth")
api.add_resource(UsuarioListResource, "/usuarios")
api.add_resource(UsuarioResource, "/usuarios/<int:id>")
api.add_resource(ProyectoListResource, "/proyectos")
api.add_resource(ProyectoResource, "/proyectos/<int:id>")
api.add_resource(ProyectoUploadResource, "/proyectos/<int:proyecto_id>/upload")
api.add_resource(VulnerabilityScanResource, "/api/sboom/<int:sboom_id>/scan")
api.add_resource(ProyectoDependenciasResource, "/proyectos/<int:proyecto_id>/dependencias")
api.add_resource(ProyectoDependenciaUpdateResource, "/proyectos/<int:proyecto_id>/dependencias/<int:dependencia_id>")
api.add_resource(RegistroPublicoResource, "/registro")
api.add_resource(SbomGenerateResource, "/proyectos/<int:proyecto_id>/sbom")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5000, debug=True)