from datetime import datetime
from flask import request, jsonify
from flask_jwt_extended import (
    create_access_token, create_refresh_token,
    get_jwt_identity, get_jwt
)
from app.extensions import db
from app.models.user_models import User, Role
from app.models.system_models import RevokedToken
from app.utils.encryption_util import encryptor

def register_user():
    """Handles user registration with encrypted PII and hashed lookups."""
    data = request.get_json()
    
    required_fields = ['username', 'email', 'password', 'role']
    if any(field not in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

    username = data['username']
    email = data['email']
    
    # Check for uniqueness using fast, indexed hashed columns
    if User.query.filter_by(username_hash=User.create_hash(username)).first():
        return jsonify({'error': 'Username already exists'}), 409
    if User.query.filter_by(email_hash=User.create_hash(email)).first():
        return jsonify({'error': 'Email already exists'}), 409
    
    role = Role.query.filter_by(name=data.get('role', 'patient')).first()
    if not role:
        return jsonify({'error': 'Invalid role'}), 400
    
    user = User(
        username=encryptor.encrypt(username), 
        email=encryptor.encrypt(email),
        username_hash=User.create_hash(username),
        email_hash=User.create_hash(email),
        role_id=role.id
    )
    try:
        user.set_password(data['password'])
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    
    db.session.add(user)
    db.session.commit()
    return jsonify({'message': 'User created successfully', 'user_id': user.id}), 201

def login_user():
    """Handles user login using fast, hashed lookups."""
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Username and password required'}), 400
    
    username = data['username']
    password = data['password']

    # Find the user via the indexed username_hash column
    user = User.query.filter_by(username_hash=User.create_hash(username)).first()
        
    if not user or not user.check_password(password):
        return jsonify({'error': 'Invalid credentials'}), 401
    if user.account_locked:
        return jsonify({'error': 'Account locked due to multiple failed attempts'}), 423
    if not user.is_active:
        return jsonify({'error': 'Account deactivated'}), 403
    if (datetime.utcnow() - user.password_changed_at).days > 90:
        user.must_change_password = True
        db.session.commit()
        return jsonify({'error': 'Password expired. Please change your password.'}), 403
    
    # Create tokens with user ID as identity and role in claims
    # NOTE: We do NOT put PII like username in the token payload.
    access_token = create_access_token(
        identity=str(user.id), additional_claims={'role': user.role.name}
    )
    refresh_token = create_refresh_token(identity=str(user.id))
    
    return jsonify({
        'access_token': access_token, 
        'refresh_token': refresh_token,
        'user': {
            'id': user.id, 
            'username': encryptor.decrypt(user.username), # Decrypt for response only
            'role': user.role.name
        }
    }), 200

def logout_user():
    jti = get_jwt()['jti']
    revoked_token = RevokedToken(jti=jti)
    db.session.add(revoked_token)
    db.session.commit()
    return jsonify({'message': 'Successfully logged out'}), 200

def refresh_token():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user or not user.is_active:
        return jsonify({'error': 'User not found or inactive'}), 403
    
    access_token = create_access_token(
        identity=user_id, additional_claims={'role': user.role.name}
    )
    return jsonify({'access_token': access_token}), 200

def change_user_password():
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