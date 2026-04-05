from datetime import datetime
import secrets
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import json

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    projects = db.relationship('HagarProject', backref='owner', lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class HagarProject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(256), nullable=True) # Optional project password
    api_token = db.Column(db.String(64), unique=True, default=lambda: secrets.token_hex(32))
    token_viewed = db.Column(db.Boolean, default=False) # Nouveau : Suivi de l'affichage
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    fields = db.relationship('HagarField', backref='project', lazy=True, cascade="all, delete-orphan")
    users = db.relationship('HagarUser', backref='project', lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        if password:
            self.password_hash = generate_password_hash(password)
        else:
            self.password_hash = None

    def check_password(self, password):
        if not self.password_hash:
            return True
        return check_password_hash(self.password_hash, password)

class HagarField(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('hagar_project.id'), nullable=False)
    label = db.Column(db.String(100), nullable=False)
    field_type = db.Column(db.String(50), nullable=False) # text, number, email, date
    is_required = db.Column(db.Boolean, default=True)

class HagarUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('hagar_project.id'), nullable=False)
    # Each registered user has at least an identifier (usually the first field) and a password
    identifier = db.Column(db.String(150), nullable=False) 
    password_hash = db.Column(db.String(256), nullable=False)
    data = db.Column(db.Text, nullable=False) # JSON data for all fields
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def get_data(self):
        return json.loads(self.data)
    
    def set_data(self, data_dict):
        self.data = json.dumps(data_dict)
