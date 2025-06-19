from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    roles = db.Column(db.String(200), nullable=False, default='user')
    is_active = db.Column(db.Boolean, default=True)
    
    # Relación con proyectos
    proyectos = db.relationship('Proyecto', backref='usuario', lazy=True, cascade='all, delete-orphan')

    @property
    def identity(self):
        return self.id

    @property
    def rolenames(self):
        try:
            return self.roles.split(',')
        except Exception:
            return []

    @property
    def password(self):
        return self.password_hash

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @classmethod
    def lookup(cls, username):
        return cls.query.filter_by(username=username).one_or_none()

    @classmethod
    def identify(cls, id):
        return cls.query.get(id)

    def is_valid(self):
        return self.is_active

    def is_admin(self):
        """Método que verifica si el usuario tiene el rol de administrador"""
        return 'admin' in self.roles.split(',')

    # Método to_dict para serializar a JSON
    def to_dict(self):
        return {
            'id': self.id,
            'nombre': self.nombre,
            'email': self.email,
            'username': self.username,
            'roles': self.roles,
            'is_active': self.is_active
        }



class Proyecto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    descripcion = db.Column(db.Text, nullable=True)
    fecha = db.Column(db.Date, nullable=False)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'), nullable=False)
    
    # Relación con SBOMs
    sbooms = db.relationship('Sboom', backref='proyecto', lazy=True, cascade='all, delete-orphan')

class Sboom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    descripcion = db.Column(db.Text, nullable=True)
    fecha = db.Column(db.Date, nullable=False)
    proyecto_id = db.Column(db.Integer, db.ForeignKey('proyecto.id'), nullable=False)
    dependencias = db.relationship('Dependencia', backref='sboom', lazy=True, cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'id': self.id,
            'nombre': self.nombre,
            'descripcion': self.descripcion,
            'fecha': self.fecha.isoformat(),
            'proyecto_id': self.proyecto_id,
            'dependencias': [d.to_dict() for d in self.dependencias]
        }

class Dependencia(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    version = db.Column(db.String(50), nullable=True)
    sboom_id = db.Column(db.Integer, db.ForeignKey('sboom.id'), nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'nombre': self.nombre,
            'version': self.version,
            'sboom_id': self.sboom_id
        }

