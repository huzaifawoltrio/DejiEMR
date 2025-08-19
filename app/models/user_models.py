# /app/models/user_models.py
from datetime import datetime, timedelta
from app.extensions import db, bcrypt

# Association table for many-to-many relationship
role_permissions = db.Table('role_permissions',
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id'), primary_key=True),
    db.Column('permission_id', db.Integer, db.ForeignKey('permissions.id'), primary_key=True)
)

class User(db.Model):
    """User model with HIPAA-compliant fields"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    # Increase the length to accommodate encrypted strings
    username = db.Column(db.String(255), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=False)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    failed_login_attempts = db.Column(db.Integer, default=0)
    account_locked = db.Column(db.Boolean, default=False)
    account_locked_until = db.Column(db.DateTime)
    password_changed_at = db.Column(db.DateTime, default=datetime.utcnow)
    must_change_password = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    
    role = db.relationship('Role', backref='users')
    audit_logs = db.relationship('AuditLog', backref='user', lazy='dynamic')
    
    def set_password(self, password: str) -> None:
        if not self._validate_password_strength(password):
            raise ValueError("Password does not meet HIPAA requirements")
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        self.password_changed_at = datetime.utcnow()
    
    def check_password(self, password: str) -> bool:
        if self.account_locked and self.account_locked_until and datetime.utcnow() < self.account_locked_until:
            return False
        elif self.account_locked:
            self.account_locked = False
            self.account_locked_until = None
            self.failed_login_attempts = 0

        is_valid = bcrypt.check_password_hash(self.password_hash, password)
        
        if not is_valid:
            self.failed_login_attempts += 1
            if self.failed_login_attempts >= 5:
                self.account_locked = True
                self.account_locked_until = datetime.utcnow() + timedelta(minutes=30)
        else:
            self.failed_login_attempts = 0
            self.last_login = datetime.utcnow()
        
        db.session.commit()
        return is_valid

    @staticmethod
    def _validate_password_strength(password: str) -> bool:
        return (len(password) >= 12 and
                any(c.isupper() for c in password) and
                any(c.islower() for c in password) and
                any(c.isdigit() for c in password) and
                any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password))

class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    permissions = db.relationship('Permission', secondary=role_permissions, backref='roles')

class Permission(db.Model):
    __tablename__ = 'permissions'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    resource = db.Column(db.String(100), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(255))