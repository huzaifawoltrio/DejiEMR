# /app/api/controllers/user_controller.py
from flask import jsonify
from flask_jwt_extended import get_jwt_identity, get_jwt
from app.models.user_models import User
from app.utils.encryption_util import encryptor

def get_all_users_list():
    """Returns a list of all users for admin, with decrypted data."""
    users = User.query.all()
    
    # Decrypt the sensitive data before sending it in the response
    decrypted_users = []
    for u in users:
        decrypted_users.append({
            'id': u.id, 
            'username': encryptor.decrypt(u.username), 
            'email': encryptor.decrypt(u.email),
            'role': u.role.name, 
            'is_active': u.is_active,
            'last_login': u.last_login.isoformat() if u.last_login else None
        })

    return jsonify({'users': decrypted_users}), 200

def test_user_auth():
    """A test endpoint to verify authentication and check claims."""
    # The username in the JWT claim is already decrypted from the login/refresh stage
    return jsonify({
        'message': 'Authentication successful', 
        'user_id': get_jwt_identity(),
        'claims': get_jwt()
    }), 200
