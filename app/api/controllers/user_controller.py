from flask import request, jsonify
from app.models.user_models import User
from app import db
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.utils.encryption_util import encryptor

def _decrypt_user_data(user):
    """Helper to decrypt a user's data for API responses."""
    if not user:
        return None

    profile_data = {}
    # Decrypts profile data based on the user's role
    if user.role.name == 'doctor' and user.doctor_profile:
        # Doctor profile fields are also encrypted and need decryption
        profile_data = {
            'first_name': encryptor.decrypt(user.doctor_profile.first_name),
            'last_name': encryptor.decrypt(user.doctor_profile.last_name),
            'specialization': user.doctor_profile.specialization, # Assuming specialization is not encrypted
        }
    elif user.role.name == 'patient' and user.patient_profile:
        # Patient profile has an encrypted 'full_name' field
        decrypted_full_name = encryptor.decrypt(user.patient_profile.full_name) or ""
        
        # Split full_name into first_name and last_name for a consistent API response
        name_parts = decrypted_full_name.split(" ", 1)
        first_name = name_parts[0]
        last_name = name_parts[1] if len(name_parts) > 1 else ""

        profile_data = {
            'first_name': first_name,
            'last_name': last_name,
            'date_of_birth': encryptor.decrypt(user.patient_profile.date_of_birth),
        }

    # Decrypt the core user fields
    decrypted_username = encryptor.decrypt(user.username)
    decrypted_email = encryptor.decrypt(user.email)
    decrypted_url = encryptor.decrypt(user.profile_picture_url) if user.profile_picture_url else None

    return {
        'id': user.id,
        'username': decrypted_username or "[decryption error]",
        'email': decrypted_email or "[decryption error]",
        'role': user.role.name if user.role else None,
        'is_active': user.is_active,
        'profile_picture_url': decrypted_url,
        'last_login': user.last_login.isoformat() if user.last_login else None,
        'created_at': user.created_at.isoformat() if user.created_at else None,
        **profile_data
    }


def get_current_user_details():
    """
    Get details for the currently authenticated user.
    """
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Use the helper to get the fully decrypted user data
    decrypted_user_data = _decrypt_user_data(user)
    
    return jsonify(decrypted_user_data), 200
