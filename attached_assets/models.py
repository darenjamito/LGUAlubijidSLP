from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from sqlalchemy.orm import DeclarativeBase

# Base class for SQLAlchemy models
class Base(DeclarativeBase):
    pass

# Initialize database with model class
db = SQLAlchemy(model_class=Base)

# Define user roles
user_roles = {
    'USER': 'user',
    'ADMIN': 'admin'
}

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    first_name = db.Column(db.String(150), nullable=False)
    last_name = db.Column(db.String(150), nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='user')
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Define relationship with files
    files = db.relationship('File', backref='user', lazy=True)
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    @property
    def is_admin(self):
        return self.role == user_roles['ADMIN']
    
    @property
    def full_name(self):
        return f"{self.first_name} {self.last_name}"

class Category(db.Model):
    __tablename__ = 'categories'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True, nullable=False)
    description = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Define relationship with files
    files = db.relationship('File', backref='category', lazy=True)
    
    def __repr__(self):
        return f'<Category {self.name}>'

class File(db.Model):
    __tablename__ = 'files'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    file_type = db.Column(db.String(50))
    file_size = db.Column(db.Integer)
    storage_path = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(20), default='active')
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Foreign keys
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'))
    
    def __repr__(self):
        return f'<File {self.filename}>'
    
    @property
    def file_size_formatted(self):
        """Return human-readable file size."""
        size = self.file_size
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024 or unit == 'GB':
                return f"{size:.2f} {unit}"
            size /= 1024
