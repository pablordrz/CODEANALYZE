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
        vulnerabilidad_display = "N/A"
        riesgo_display = "N/A"
        
        if self.vulnerabilidades:
            severidades = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            max_vuln = None
            max_riesgo_num = 0
            
            for v in self.vulnerabilidades:
                riesgo_num = severidades.get(v.severidad.upper(), 0) if v.severidad else 0
                if riesgo_num > max_riesgo_num:
                    max_riesgo_num = riesgo_num
                    max_vuln = v
            
            if max_vuln:
                vulnerabilidad_display = max_vuln.cve_id
                riesgo_display = max_vuln.severidad

        return {
            'id': self.id,
            'nombre': self.nombre,
            'version': self.version or "No especificada",
            'sboom_id': self.sboom_id,
            'vulnerabilidad_display': vulnerabilidad_display,  # CVE de mayor riesgo
            'nivel_riesgo_display': riesgo_display,            # Severidad de mayor riesgo
            'vulnerabilidades': [v.to_dict() for v in self.vulnerabilidades]
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