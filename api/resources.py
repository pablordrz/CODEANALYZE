from flask_restful import Resource, reqparse
from flask import request
from models import db, Usuario, Proyecto
from datetime import datetime
from flask_praetorian import auth_required, roles_required, roles_accepted, current_user

usuario_parser = reqparse.RequestParser()
usuario_parser.add_argument("nombre", type=str, required=True)
usuario_parser.add_argument("email", type=str, required=True)
usuario_parser.add_argument("username", type=str, required=True)
usuario_parser.add_argument("password", type=str, required=False)
usuario_parser.add_argument("is_admin", type=bool, default=False)

proyecto_parser = reqparse.RequestParser()
proyecto_parser.add_argument("nombre", type=str, required=True)
proyecto_parser.add_argument("descripcion", type=str)
proyecto_parser.add_argument("fecha", type=str, required=True)

class UsuarioListResource(Resource):
    @roles_required('admin')
    def get(self):
        usuarios = Usuario.query.all()
        return [{
            "id": u.id, 
            "nombre": u.nombre, 
            "email": u.email,
            "username": u.username, 
            "rol": u.roles.split(',')[0] if isinstance(u.roles, str) else u.roles
        } for u in usuarios]
    
    @roles_required('admin')  # Solo administradores pueden crear
    def post(self):
        data = request.get_json()
        if not data:
            return {"error": "No se recibió JSON válido."}, 400

        nombre = data.get("nombre")
        email = data.get("email")
        username = data.get("username")
        password = data.get("password")
        is_admin = data.get("is_admin", False)

        # Verificar campos obligatorios
        if not all([nombre, email, username, password]):
            return {"error": "Faltan campos obligatorios."}, 400

        # Verificar unicidad de username y email
        if Usuario.query.filter_by(username=username).first():
            return {"error": "El nombre de usuario ya está en uso."}, 400
        if Usuario.query.filter_by(email=email).first():
            return {"error": "El correo electrónico ya está registrado."}, 400

        # Crear el nuevo usuario
        nuevo_usuario = Usuario(
            nombre=nombre,
            email=email,
            username=username,
            roles='admin' if is_admin else 'user'
        )
        nuevo_usuario.password = password  # Setter hash automático

        db.session.add(nuevo_usuario)
        db.session.commit()

        return {
            "message": "Usuario creado exitosamente.",
            "usuario": nuevo_usuario.to_dict()
        }, 201


class UsuarioResource(Resource):
    @auth_required
    def get(self, id):
        user = current_user()
        # Comprobar el rol del usuario
        user_role = None
        if hasattr(user, 'roles'):
            if isinstance(user.roles, str):
                user_role = user.roles.split(',')[0]
            else:
                user_role = user.roles
        elif hasattr(user, 'rolenames'):
            user_role = user.rolenames[0] if user.rolenames else None
        if user_role != 'admin' and user.id != id:
            return {"error": "No autorizado"}, 403
        u = Usuario.query.get_or_404(id)
        return {
            "id": u.id, "nombre": u.nombre, "email": u.email,
            "username": u.username, "rol": u.roles.split(',')[0] if isinstance(u.roles, str) else u.roles
        }

    @roles_required('admin')
    def put(self, id):
        u = Usuario.query.get_or_404(id)
        args = usuario_parser.parse_args()
        u.nombre = args["nombre"]
        u.email = args["email"]
        u.username = args["username"]
        u.roles = 'admin' if args["is_admin"] else 'user'
        if args["password"]:
            u.set_password(args["password"])
        db.session.commit()
        return {"message": "Usuario actualizado"}

    @roles_required('admin')
    def delete(self, id):
        u = Usuario.query.get_or_404(id)
        db.session.delete(u)
        db.session.commit()
        return {"message": "Usuario eliminado"}

class ProyectoListResource(Resource):
    @auth_required
    def get(self):
        user = current_user()
        # Comprobar el rol del usuario
        user_role = None
        if hasattr(user, 'roles'):
            if isinstance(user.roles, str):
                user_role = user.roles.split(',')[0]
            else:
                user_role = user.roles
        elif hasattr(user, 'rolenames'):
            user_role = user.rolenames[0] if user.rolenames else None

        print(f"Usuario actual: {user.id}, Rol: {user_role}")

        try:
            if user_role == 'admin':
                usuario_id = request.args.get("usuario_id", type=int)
                if usuario_id:
                    proyectos = Proyecto.query.filter_by(usuario_id=usuario_id).all()
                else:
                    proyectos = Proyecto.query.all()
            else:
                proyectos = Proyecto.query.filter_by(usuario_id=user.id).all()

            print(f"Proyectos obtenidos: {proyectos}")
            
            return [{
                "id": p.id, "nombre": p.nombre, "descripcion": p.descripcion,
                "fecha": p.fecha.isoformat(), "usuario_id": p.usuario_id
            } for p in proyectos]
        except Exception as e:
            print(f"Error al obtener proyectos: {e}")
            return {"error": "No se pudieron obtener los proyectos"}, 500
        
    
    @auth_required
    def post(self):
        user = current_user()
        args = proyecto_parser.parse_args()

        nuevo_proyecto = Proyecto(
            nombre=args["nombre"],
            descripcion=args["descripcion"],
            fecha=datetime.strptime(args["fecha"], "%Y-%m-%d").date(),
            usuario_id=user.id  # ✅ asignado desde el token
        )

        db.session.add(nuevo_proyecto)
        db.session.commit()

        return {
            "id": nuevo_proyecto.id,
            "nombre": nuevo_proyecto.nombre,
            "descripcion": nuevo_proyecto.descripcion,
            "fecha": nuevo_proyecto.fecha.isoformat(),
            "usuario_id": nuevo_proyecto.usuario_id
        }, 201
    
class ProyectoResource(Resource):
    @auth_required
    def get(self, id):
        user = current_user()
        # Comprobar el rol del usuario
        user_role = None
        if hasattr(user, 'roles'):
            if isinstance(user.roles, str):
                user_role = user.roles.split(',')[0]
            else:
                user_role = user.roles
        elif hasattr(user, 'rolenames'):
            user_role = user.rolenames[0] if user.rolenames else None
        p = Proyecto.query.get_or_404(id)
        if user_role != 'admin' and p.usuario_id != user.id:
            return {"error": "No autorizado"}, 403
        return {
            "id": p.id, "nombre": p.nombre, "descripcion": p.descripcion,
            "fecha": p.fecha.isoformat(), "usuario_id": p.usuario_id
        }

    @auth_required
    def put(self, id):
        user = current_user()
        # Comprobar el rol del usuario
        user_role = None
        if hasattr(user, 'roles'):
            if isinstance(user.roles, str):
                user_role = user.roles.split(',')[0]
            else:
                user_role = user.roles
        elif hasattr(user, 'rolenames'):
            user_role = user.rolenames[0] if user.rolenames else None
        p = Proyecto.query.get_or_404(id)
        if user_role != 'admin' and p.usuario_id != user.id:
            return {"error": "No autorizado"}, 403
        args = proyecto_parser.parse_args()
        p.nombre = args["nombre"]
        p.descripcion = args["descripcion"]
        p.fecha = datetime.strptime(args["fecha"], "%Y-%m-%d").date()
        db.session.commit()
        return {"message": "Proyecto actualizado"}

    @auth_required
    def delete(self, id):
        user = current_user()
        # Comprobar el rol del usuario
        user_role = None
        if hasattr(user, 'roles'):
            if isinstance(user.roles, str):
                user_role = user.roles.split(',')[0]
            else:
                user_role = user.roles
        elif hasattr(user, 'rolenames'):
            user_role = user.rolenames[0] if user.rolenames else None
        
        try:
            p = Proyecto.query.get_or_404(id)
            if user_role != 'admin' and p.usuario_id != user.id:
                return {"error": "No autorizado"}, 403
            
            # Obtener información del proyecto antes de borrarlo
            proyecto_info = {
                "id": p.id,
                "nombre": p.nombre,
                "usuario_id": p.usuario_id
            }
            
            # El borrado en cascada se maneja automáticamente por SQLAlchemy
            # debido a las relaciones configuradas en los modelos
            db.session.delete(p)
            db.session.commit()
            
            return {
                "message": f"Proyecto '{proyecto_info['nombre']}' eliminado exitosamente",
                "proyecto_eliminado": proyecto_info
            }, 200
            
        except Exception as e:
            db.session.rollback()
            print(f"Error al eliminar proyecto {id}: {str(e)}")
            return {"error": "Error interno al eliminar el proyecto"}, 500
    
