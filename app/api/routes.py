# /app/api/routes.py
from datetime import datetime
from flask import request, jsonify
from flask_jwt_extended import (
    create_access_token, create_refresh_token, jwt_required,
    get_jwt_identity, get_jwt
)
from . import api_bp
from app.extensions import db, limiter
from app.models.user_models import User, Role
from app.models.system_models import RevokedToken
from app.utils.decorators import audit_log, require_permission

# --- Authentication Endpoints ---

@api_bp.route('/auth/register', methods=['POST'])
@limiter.limit("5 per hour")
@audit_log("USER_REGISTRATION", "users")
def register():
    data = request.get_json()
    
    # Check for missing required fields and give a specific error
    required_fields = ['username', 'email', 'password', 'role']
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        return jsonify({'error': f"Missing required fields: {', '.join(missing_fields)}"}), 400

    if User.query.filter((User.username == data['username']) | (User.email == data['email'])).first():
        return jsonify({'error': 'Username or email already exists'}), 409
    
    role = Role.query.filter_by(name=data.get('role', 'patient')).first()
    if not role:
        return jsonify({'error': 'Invalid role'}), 400
    
    user = User(username=data['username'], email=data['email'], role_id=role.id)
    try:
        user.set_password(data['password'])
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User created successfully', 'user_id': user.id}), 201

@api_bp.route('/auth/login', methods=['POST'])
@limiter.limit("10 per minute")
@audit_log("USER_LOGIN", "authentication")
def login():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Username and password required'}), 400
    
    user = User.query.filter_by(username=data['username']).first()
    
    if not user or not user.check_password(data['password']):
        return jsonify({'error': 'Invalid credentials'}), 401
    if user.account_locked:
        return jsonify({'error': 'Account locked due to multiple failed attempts'}), 423
    if not user.is_active:
        return jsonify({'error': 'Account deactivated'}), 403
    if (datetime.utcnow() - user.password_changed_at).days > 90:
        user.must_change_password = True
        db.session.commit()
        return jsonify({'error': 'Password expired. Please change your password.'}), 403
        
    access_token = create_access_token(identity=str(user.id), additional_claims={'role': user.role.name, 'username': user.username})
    refresh_token = create_refresh_token(identity=str(user.id))
    
    return jsonify({
        'access_token': access_token, 'refresh_token': refresh_token,
        'user': {'id': user.id, 'username': user.username, 'role': user.role.name}
    }), 200

@api_bp.route('/auth/logout', methods=['POST'])
@jwt_required()
@audit_log("USER_LOGOUT", "authentication")
def logout():
    jti = get_jwt()['jti']
    exp = get_jwt()['exp']
    revoked_token = RevokedToken(jti=jti, expires_at=datetime.fromtimestamp(exp))
    db.session.add(revoked_token)
    db.session.commit()
    return jsonify({'message': 'Successfully logged out'}), 200

@api_bp.route('/auth/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user or not user.is_active:
        return jsonify({'error': 'User not found or inactive'}), 403
    
    access_token = create_access_token(identity=user_id, additional_claims={'role': user.role.name, 'username': user.username})
    return jsonify({'access_token': access_token}), 200

@api_bp.route('/auth/change-password', methods=['POST'])
@jwt_required()
@audit_log("PASSWORD_CHANGE", "authentication")
def change_password():
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

# --- Protected Example Endpoints ---

@api_bp.route('/patients', methods=['GET'])
@require_permission('patients', 'read')
@audit_log("VIEW_PATIENTS", "patients")
def get_patients():
    return jsonify({'message': 'Patient list (placeholder)', 'total': 0}), 200

@api_bp.route('/test-auth', methods=['GET'])
@jwt_required()
def test_auth():
    return jsonify({
        'message': 'Authentication successful', 'user_id': get_jwt_identity(),
        'claims': get_jwt()
    }), 200

@api_bp.route('/admin/users', methods=['GET'])
@require_permission('users', 'admin')
@audit_log("VIEW_ALL_USERS", "users")
def get_all_users():
    users = User.query.all()
    return jsonify({
        'users': [{
            'id': u.id, 'username': u.username, 'email': u.email,
            'role': u.role.name, 'is_active': u.is_active,
            'last_login': u.last_login.isoformat() if u.last_login else None
        } for u in users]
    }), 200
