# /app/api/controllers/auth_controller.py
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
    """Handles the logic for user registration with encryption."""
    data = request.get_json()
    
    required_fields = ['username', 'email', 'password', 'role']
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        return jsonify({'error': f"Missing required fields: {', '.join(missing_fields)}"}), 400

    # Encrypt sensitive PII (Personally Identifiable Information)
    encrypted_email = encryptor.encrypt(data['email'])
    encrypted_username = encryptor.encrypt(data['username'])

    # Check if the username or email already exists by decrypting stored values.
    # Note: This is inefficient for large datasets. A hashed column for lookups is a better practice.
    users = User.query.all()
    for user in users:
        if encryptor.decrypt(user.username) == data['username'] or encryptor.decrypt(user.email) == data['email']:
            return jsonify({'error': 'Username or email already exists'}), 409
    
    role = Role.query.filter_by(name=data.get('role', 'patient')).first()
    if not role:
        return jsonify({'error': 'Invalid role'}), 400
    
    # Create user with encrypted data
    user = User(
        username=encrypted_username, 
        email=encrypted_email, 
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
    """Handles the logic for user login with decryption."""
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Username and password required'}), 400
    
    # Since username is encrypted, we must iterate to find the user.
    # This is INEFFICIENT and not suitable for production with many users.
    users = User.query.all()
    user = None
    for u in users:
        if encryptor.decrypt(u.username) == data['username']:
            user = u
            break
            
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
    
    # Decrypt username for the JWT payload and response
    decrypted_username = encryptor.decrypt(user.username)
        
    access_token = create_access_token(identity=str(user.id), additional_claims={'role': user.role.name, 'username': decrypted_username})
    refresh_token = create_refresh_token(identity=str(user.id))
    
    return jsonify({
        'access_token': access_token, 'refresh_token': refresh_token,
        'user': {'id': user.id, 'username': decrypted_username, 'role': user.role.name}
    }), 200

def logout_user():
    """Handles the logic for user logout by revoking the token."""
    jti = get_jwt()['jti']
    exp = get_jwt()['exp']
    revoked_token = RevokedToken(jti=jti, expires_at=datetime.fromtimestamp(exp))
    db.session.add(revoked_token)
    db.session.commit()
    return jsonify({'message': 'Successfully logged out'}), 200

def refresh_token():
    """Handles the logic for refreshing an access token."""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user or not user.is_active:
        return jsonify({'error': 'User not found or inactive'}), 403
    
    decrypted_username = encryptor.decrypt(user.username)
    
    access_token = create_access_token(identity=user_id, additional_claims={'role': user.role.name, 'username': decrypted_username})
    return jsonify({'access_token': access_token}), 200

def change_user_password():
    """Handles the logic for changing a user's password."""
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
