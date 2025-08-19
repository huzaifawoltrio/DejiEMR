# HIPAA-Compliant EMR API with JWT Authentication and RBAC
# requirements.txt:
# Flask==2.3.0
# Flask-JWT-Extended==4.5.0
# Flask-SQLAlchemy==3.0.0
# Flask-Bcrypt==1.0.1
# Flask-Migrate==4.0.0
# python-dotenv==1.0.0
# cryptography==41.0.0
# Flask-Limiter==3.3.0
# Flask-CORS==4.0.0

import os
import secrets
import logging
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Optional, Dict, Any

from flask import Flask, request, jsonify
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt, verify_jwt_in_request
)
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from sqlalchemy import event
from sqlalchemy.orm import Session
import hashlib

# Initialize Flask app
app = Flask(__name__)

# HIPAA-Compliant Configuration
class Config:
    """HIPAA-compliant configuration settings"""
    # Security
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or secrets.token_hex(32)
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(minutes=15)  # Short-lived for security
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=1)
    JWT_BLACKLIST_ENABLED = True
    JWT_BLACKLIST_TOKEN_CHECKS = ['access', 'refresh']
    
    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'postgresql://user:pass@localhost/emr_db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
    }
    
    # Security Headers
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'
    
    # Rate Limiting (prevents brute force)
    RATELIMIT_STORAGE_URL = os.environ.get('REDIS_URL') or 'memory://'

app.config.from_object(Config)

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
migrate = Migrate(app, db)
limiter = Limiter(app, key_func=get_remote_address)
CORS(app, origins=os.environ.get('ALLOWED_ORIGINS', '').split(','))

# Configure HIPAA-compliant logging
logging.basicConfig(
    filename='emr_audit.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
audit_logger = logging.getLogger('HIPAA_AUDIT')

# Database Models
class User(db.Model):
    """User model with HIPAA-compliant fields"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=False)
    
    # HIPAA compliance fields
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    failed_login_attempts = db.Column(db.Integer, default=0)
    account_locked = db.Column(db.Boolean, default=False)
    account_locked_until = db.Column(db.DateTime)
    password_changed_at = db.Column(db.DateTime, default=datetime.utcnow)
    must_change_password = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    role = db.relationship('Role', backref='users')
    audit_logs = db.relationship('AuditLog', backref='user', lazy='dynamic')
    
    def set_password(self, password: str) -> None:
        """Hash and set password with HIPAA-compliant strength requirements"""
        if not self._validate_password_strength(password):
            raise ValueError("Password does not meet HIPAA requirements")
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        self.password_changed_at = datetime.utcnow()
    
    def check_password(self, password: str) -> bool:
        """Verify password with account lockout protection"""
        if self.account_locked and self.account_locked_until:
            if datetime.utcnow() < self.account_locked_until:
                return False
            else:
                self.account_locked = False
                self.account_locked_until = None
                self.failed_login_attempts = 0
        
        is_valid = bcrypt.check_password_hash(self.password_hash, password)
        
        if not is_valid:
            self.failed_login_attempts += 1
            if self.failed_login_attempts >= 5:
                self.account_locked = True
                self.account_locked_until = datetime.utcnow() + timedelta(minutes=30)
            db.session.commit()
        else:
            self.failed_login_attempts = 0
            self.last_login = datetime.utcnow()
            db.session.commit()
        
        return is_valid
    
    @staticmethod
    def _validate_password_strength(password: str) -> bool:
        """HIPAA-compliant password validation"""
        if len(password) < 12:
            return False
        if not any(c.isupper() for c in password):
            return False
        if not any(c.islower() for c in password):
            return False
        if not any(c.isdigit() for c in password):
            return False
        if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
            return False
        return True

class Role(db.Model):
    """Role model for RBAC"""
    __tablename__ = 'roles'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    permissions = db.relationship('Permission', secondary='role_permissions', backref='roles')

class Permission(db.Model):
    """Permission model"""
    __tablename__ = 'permissions'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    resource = db.Column(db.String(100), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(255))

# Association table for many-to-many relationship
role_permissions = db.Table('role_permissions',
    db.Column('role_id', db.Integer, db.ForeignKey('roles.id'), primary_key=True),
    db.Column('permission_id', db.Integer, db.ForeignKey('permissions.id'), primary_key=True)
)

class AuditLog(db.Model):
    """HIPAA-required audit logging"""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    action = db.Column(db.String(100), nullable=False)
    resource = db.Column(db.String(100))
    resource_id = db.Column(db.String(100))
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(255))
    success = db.Column(db.Boolean, default=True)
    details = db.Column(db.Text)

class RevokedToken(db.Model):
    """Track revoked JWT tokens"""
    __tablename__ = 'revoked_tokens'
    
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(120), unique=True, nullable=False, index=True)
    revoked_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)

# Audit logging decorator
def audit_log(action: str, resource: str = None):
    """Decorator for HIPAA-compliant audit logging"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                result = f(*args, **kwargs)
                
                # Log successful action
                try:
                    verify_jwt_in_request(optional=True)
                    user_id = get_jwt_identity()
                except:
                    user_id = None
                
                log_entry = AuditLog(
                    user_id=user_id,
                    action=action,
                    resource=resource,
                    resource_id=kwargs.get('id'),
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent'),
                    success=True
                )
                db.session.add(log_entry)
                db.session.commit()
                
                audit_logger.info(f"Action: {action}, User: {user_id}, Resource: {resource}, IP: {request.remote_addr}")
                
                return result
            except Exception as e:
                # Log failed action
                try:
                    user_id = get_jwt_identity()
                except:
                    user_id = None
                
                log_entry = AuditLog(
                    user_id=user_id,
                    action=action,
                    resource=resource,
                    resource_id=kwargs.get('id'),
                    ip_address=request.remote_addr,
                    user_agent=request.headers.get('User-Agent'),
                    success=False,
                    details=str(e)
                )
                db.session.add(log_entry)
                db.session.commit()
                
                audit_logger.error(f"Failed Action: {action}, User: {user_id}, Error: {str(e)}")
                raise
        return decorated_function
    return decorator

# RBAC decorator
def require_permission(resource: str, action: str):
    """Decorator for role-based access control"""
    def decorator(f):
        @wraps(f)
        @jwt_required()
        def decorated_function(*args, **kwargs):
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            
            if not user or not user.is_active:
                return jsonify({'error': 'User not found or inactive'}), 403
            
            # Superadmin bypass
            if user.role.name == 'superadmin':
                return f(*args, **kwargs)
            
            # Check permissions
            has_permission = any(
                p.resource == resource and p.action == action 
                for p in user.role.permissions
            )
            
            if not has_permission:
                audit_logger.warning(f"Permission denied: User {user_id} attempted {action} on {resource}")
                return jsonify({'error': 'Insufficient permissions'}), 403
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# JWT callbacks
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    token = RevokedToken.query.filter_by(jti=jti).first()
    return token is not None

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({'error': 'Token has expired', 'message': 'Please refresh your token or login again'}), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({'error': 'Invalid token', 'message': str(error)}), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({'error': 'Authorization required', 'message': 'No valid authorization header found'}), 401

@jwt.revoked_token_loader
def revoked_token_callback(jwt_header, jwt_payload):
    return jsonify({'error': 'Token has been revoked', 'message': 'This token has been logged out'}), 401

# Authentication endpoints
@app.route('/api/auth/register', methods=['POST'])
@limiter.limit("5 per hour")
@audit_log("USER_REGISTRATION", "users")
def register():
    """Register a new user with HIPAA compliance"""
    data = request.get_json()
    
    # Validate input
    required_fields = ['username', 'email', 'password', 'role']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Check if user exists
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 409
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already exists'}), 409
    
    # Get role
    role = Role.query.filter_by(name=data.get('role', 'user')).first()
    if not role:
        return jsonify({'error': 'Invalid role'}), 400
    
    # Create user
    user = User(
        username=data['username'],
        email=data['email'],
        role_id=role.id
    )
    
    try:
        user.set_password(data['password'])
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    
    db.session.add(user)
    db.session.commit()
    
    return jsonify({'message': 'User created successfully', 'user_id': user.id}), 201

@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("10 per minute")
@audit_log("USER_LOGIN", "authentication")
def login():
    """Login with HIPAA-compliant authentication"""
    data = request.get_json()
    
    if not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Username and password required'}), 400
    
    user = User.query.filter_by(username=data['username']).first()
    
    if not user or not user.check_password(data['password']):
        audit_logger.warning(f"Failed login attempt for username: {data.get('username')}")
        return jsonify({'error': 'Invalid credentials'}), 401
    
    if user.account_locked:
        return jsonify({'error': 'Account locked due to multiple failed attempts'}), 423
    
    if not user.is_active:
        return jsonify({'error': 'Account deactivated'}), 403
    
    # Check password expiry (90 days for HIPAA)
    if (datetime.utcnow() - user.password_changed_at).days > 90:
        user.must_change_password = True
        db.session.commit()
        return jsonify({'error': 'Password expired. Please change your password.'}), 403
    
    # Create tokens
    access_token = create_access_token(
        identity=str(user.id),  
        additional_claims={
            'role': user.role.name,
            'username': user.username
        }
    )
    refresh_token = create_refresh_token(identity=str(user.id))
    
    return jsonify({
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user': {
            'id': user.id,
            'username': user.username,
            'role': user.role.name
        }
    }), 200

@app.route('/api/auth/logout', methods=['POST'])
@jwt_required()
@audit_log("USER_LOGOUT", "authentication")
def logout():
    """Logout and revoke token"""
    jti = get_jwt()['jti']
    exp = get_jwt()['exp']
    
    revoked_token = RevokedToken(
        jti=jti,
        expires_at=datetime.fromtimestamp(exp)
    )
    db.session.add(revoked_token)
    db.session.commit()
    
    return jsonify({'message': 'Successfully logged out'}), 200

@app.route('/api/auth/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Refresh access token"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user or not user.is_active:
        return jsonify({'error': 'User not found or inactive'}), 403
    
    access_token = create_access_token(
        identity=user_id,
        additional_claims={
            'role': user.role.name,
            'username': user.username
        }
    )
    
    return jsonify({'access_token': access_token}), 200

@app.route('/api/auth/change-password', methods=['POST'])
@jwt_required()
@audit_log("PASSWORD_CHANGE", "authentication")
def change_password():
    """Change user password with HIPAA compliance"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    data = request.get_json()
    
    if not data.get('current_password') or not data.get('new_password'):
        return jsonify({'error': 'Current and new passwords required'}), 400
    
    if not user.check_password(data['current_password']):
        return jsonify({'error': 'Invalid current password'}), 401
    
    try:
        user.set_password(data['new_password'])
        user.must_change_password = False
        db.session.commit()
        return jsonify({'message': 'Password changed successfully'}), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

# Protected example endpoints
@app.route('/api/patients', methods=['GET'])
@require_permission('patients', 'read')
@audit_log("VIEW_PATIENTS", "patients")
def get_patients():
    """Example endpoint - Get all patients (requires permission)"""
    return jsonify({'message': 'Patient list (placeholder)', 'total': 0}), 200

@app.route('/api/test-auth', methods=['GET'])
@jwt_required()
def test_auth():
    """Test endpoint to verify JWT authentication is working"""
    current_user_id = get_jwt_identity()
    jwt_data = get_jwt()
    
    return jsonify({
        'message': 'Authentication successful',
        'user_id': current_user_id,
        'username': jwt_data.get('username'),
        'role': jwt_data.get('role'),
        'token_type': jwt_data.get('type', 'access')
    }), 200

@app.route('/api/admin/users', methods=['GET'])
@require_permission('users', 'admin')
@audit_log("VIEW_ALL_USERS", "users")
def get_all_users():
    """Superadmin endpoint - Get all users"""
    users = User.query.all()
    return jsonify({
        'users': [{
            'id': u.id,
            'username': u.username,
            'email': u.email,
            'role': u.role.name,
            'is_active': u.is_active,
            'last_login': u.last_login.isoformat() if u.last_login else None
        } for u in users]
    }), 200

# Database initialization
@app.cli.command('init-db')
def init_database():
    """Initialize database with HIPAA-compliant schema"""
    db.create_all()
    
    # Create default roles
    roles_data = [
        {'name': 'superadmin', 'description': 'Full system access'},
        {'name': 'admin', 'description': 'Administrative access'},
        {'name': 'doctor', 'description': 'Medical professional access'},
        {'name': 'nurse', 'description': 'Nursing staff access'},
        {'name': 'staff', 'description': 'General staff access'},
        {'name': 'patient', 'description': 'Patient portal access'}
    ]
    
    for role_data in roles_data:
        if not Role.query.filter_by(name=role_data['name']).first():
            role = Role(**role_data)
            db.session.add(role)
    
    # Create default permissions
    permissions_data = [
        {'name': 'admin_all', 'resource': '*', 'action': '*', 'description': 'Full administrative access'},
        {'name': 'read_patients', 'resource': 'patients', 'action': 'read', 'description': 'View patient records'},
        {'name': 'write_patients', 'resource': 'patients', 'action': 'write', 'description': 'Create/update patient records'},
        {'name': 'delete_patients', 'resource': 'patients', 'action': 'delete', 'description': 'Delete patient records'},
        {'name': 'admin_users', 'resource': 'users', 'action': 'admin', 'description': 'Administer user accounts'},
        {'name': 'view_audit', 'resource': 'audit', 'action': 'read', 'description': 'View audit logs'},
    ]
    
    for perm_data in permissions_data:
        if not Permission.query.filter_by(name=perm_data['name']).first():
            permission = Permission(**perm_data)
            db.session.add(permission)
    
    db.session.commit()
    
    # Assign all permissions to superadmin
    superadmin = Role.query.filter_by(name='superadmin').first()
    all_permissions = Permission.query.all()
    superadmin.permissions = all_permissions
    db.session.commit()
    
    print("Database initialized successfully!")

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    audit_logger.error(f"Internal server error: {str(error)}")
    return jsonify({'error': 'Internal server error'}), 500

# Security headers middleware
@app.after_request
def set_security_headers(response):
    """Set HIPAA-compliant security headers"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

if __name__ == '__main__':
    # Never run with debug=True in production
    app.run(debug=False, ssl_context='adhoc')  # Use proper SSL certificates in production