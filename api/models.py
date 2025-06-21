from flask_sqlalchemy import SQLAlchemy
from passlib.hash import bcrypt

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
        self.password_hash = bcrypt.hash(password)

    def check_password(self, password):
        return bcrypt.verify(password, self.password_hash)

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
    
    # Nuevas columnas para configuración de seguridad
    max_vulnerabilidades_permitidas = db.Column(db.Integer, nullable=True, default=None)
    nivel_criticidad_maximo = db.Column(db.String(20), nullable=True, default=None)  # LOW, MEDIUM, HIGH, CRITICAL
    
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
    vulnerabilidades = db.relationship('Vulnerabilidad', backref='dependencia', lazy=True, cascade="all, delete-orphan")

    def to_dict(self):
        """
        Serializa el objeto Dependencia a un diccionario, incluyendo sus vulnerabilidades.
        Esta es la función clave para que el frontend pueda mostrar los datos.
        """
        # Determina la vulnerabilidad y el nivel de riesgo para la tabla
        vulnerabilidad_display = "N/A"
        riesgo_display = "N/A"
        if self.vulnerabilidades:
            num_vulns = len(self.vulnerabilidades)
            vulnerabilidad_display = f"{num_vulns} encontrada{'s' if num_vulns > 1 else ''}"
            
            # Calcula el nivel de riesgo más alto
            severidades = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            max_riesgo_num = 0
            for v in self.vulnerabilidades:
                riesgo_num = severidades.get(v.severidad, 0)
                if riesgo_num > max_riesgo_num:
                    max_riesgo_num = riesgo_num
                    riesgo_display = v.severidad

        return {
            'id': self.id,
            'nombre': self.nombre,
            'version': self.version or "No especificada",
            'sboom_id': self.sboom_id,
            'vulnerabilidad_display': vulnerabilidad_display, # Columna "Vulnerabilidad"
            'nivel_riesgo_display': riesgo_display,       # Columna "Nivel de Riesgo"
            'vulnerabilidades': [v.to_dict() for v in self.vulnerabilidades] # Lista detallada
        }

class Vulnerabilidad(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(50), nullable=False)
    descripcion = db.Column(db.Text, nullable=False)
    puntuacion_cvss = db.Column(db.Float, nullable=True)
    severidad = db.Column(db.String(50), nullable=True)
    dependencia_id = db.Column(db.Integer, db.ForeignKey('dependencia.id'), nullable=False)
    
    __table_args__ = (db.UniqueConstraint('cve_id', 'dependencia_id', name='_cve_dependencia_uc'),)

    def to_dict(self):
        return {
            'id': self.id,
            'cve_id': self.cve_id,
            'descripcion': self.descripcion,
            'puntuacion_cvss': self.puntuacion_cvss,
            'severidad': self.severidad
        }