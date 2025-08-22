# /app/api/controllers/profile_controller.py
from flask import request, jsonify
from flask_jwt_extended import get_jwt_identity
from app.extensions import db
from app.models.user_models import User
from app.utils.encryption_util import encryptor
from app.utils.cloudinary_util import cloudinary_manager

def upload_profile_picture():
    """Upload profile picture for the authenticated user."""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Debug: Log what files are in the request
    from flask import current_app
    current_app.logger.info(f"Request files keys: {list(request.files.keys())}")
    
    # Check for common file field names
    file = None
    possible_keys = ['file', 'picture', 'image', 'profilePicture', 'profile_picture']
    
    for key in possible_keys:
        if key in request.files:
            file = request.files[key]
            current_app.logger.info(f"Found file with key: {key}")
            break
    
    if file is None:
        return jsonify({
            'error': 'No file provided', 
            'available_keys': list(request.files.keys()),
            'expected_keys': possible_keys
        }), 400
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Determine user type for naming
    user_type = user.role.name if user.role else 'user'
    
    # Delete old profile picture if exists
    if user.profile_picture_url and user.profile_picture_public_id:
        try:
            decrypted_public_id = encryptor.decrypt(user.profile_picture_public_id)
            if decrypted_public_id:
                cloudinary_manager.delete_profile_picture(decrypted_public_id)
        except Exception as e:
            current_app.logger.error(f"Error deleting old profile picture: {str(e)}")
    
    # Upload new profile picture
    upload_result = cloudinary_manager.upload_profile_picture(file, user_id, user_type)
    
    if not upload_result['success']:
        return jsonify({'error': upload_result['error']}), 400
    
    # Update user record with encrypted URL and public_id
    try:
        original_url = upload_result['url']
        original_public_id = upload_result['public_id']

        # Encrypt ONLY ONCE
        encrypted_url = encryptor.encrypt(original_url)
        encrypted_public_id = encryptor.encrypt(original_public_id)

        current_app.logger.info(f"Original URL length: {len(original_url)}")
        current_app.logger.info(f"Encrypted URL length: {len(encrypted_url)}")
        current_app.logger.info(f"Database column limit is 1024 characters.")
        
        # Use the already encrypted values
        user.profile_picture_url = encrypted_url
        user.profile_picture_public_id = encrypted_public_id
        
        db.session.commit()
        
        return jsonify({
            'message': 'Profile picture uploaded successfully',
            'profile_picture_url': original_url  # Return the original (unencrypted) URL to client
        }), 200
        
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Database error: {str(e)}")
        
        # Clean up uploaded image if database update fails
        try:
            cloudinary_manager.delete_profile_picture(upload_result['public_id'])
        except Exception as delete_error:
            current_app.logger.error(f"Error cleaning up Cloudinary image: {str(delete_error)}")
        
        return jsonify({'error': 'Failed to update profile picture in database'}), 500
    
def get_profile_picture():
    """Get the current user's profile picture URL."""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if not user.profile_picture_url:
        return jsonify({'profile_picture_url': None}), 200
    
    decrypted_url = encryptor.decrypt(user.profile_picture_url)
    return jsonify({'profile_picture_url': decrypted_url}), 200

def delete_profile_picture():
    """Delete the current user's profile picture."""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if not user.profile_picture_url:
        return jsonify({'message': 'No profile picture to delete'}), 200
    
    # Delete from Cloudinary
    if user.profile_picture_public_id:
        decrypted_public_id = encryptor.decrypt(user.profile_picture_public_id)
        if decrypted_public_id:
            delete_result = cloudinary_manager.delete_profile_picture(decrypted_public_id)
            if not delete_result['success']:
                return jsonify({'error': 'Failed to delete image from cloud storage'}), 500
    
    # Update database
    try:
        user.profile_picture_url = None
        user.profile_picture_public_id = None
        db.session.commit()
        
        return jsonify({'message': 'Profile picture deleted successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to update profile'}), 500

def get_user_profile_picture(target_user_id):
    """Get another user's profile picture (with permission checks)."""
    current_user_id = get_jwt_identity()
    current_user = User.query.get(current_user_id)
    target_user = User.query.get(target_user_id)
    
    if not target_user:
        return jsonify({'error': 'User not found'}), 404
    
    # Permission check: only allow if user is admin, superadmin, or it's their own profile
    allowed_roles = ['admin', 'superadmin']
    if (current_user.role.name not in allowed_roles and 
        int(current_user_id) != int(target_user_id)):
        
        # Additional check: doctors can see their patients' pictures
        if current_user.role.name == 'doctor':
            is_assigned_patient = current_user.assigned_patients.filter_by(id=target_user_id).first()
            if not is_assigned_patient:
                return jsonify({'error': 'Permission denied'}), 403
        # Patients can see their doctors' pictures
        elif current_user.role.name == 'patient':
            is_assigned_doctor = current_user.assigned_doctors.filter_by(id=target_user_id).first()
            if not is_assigned_doctor:
                return jsonify({'error': 'Permission denied'}), 403
        else:
            return jsonify({'error': 'Permission denied'}), 403
    
    if not target_user.profile_picture_url:
        return jsonify({'profile_picture_url': None}), 200
    
    decrypted_url = encryptor.decrypt(target_user.profile_picture_url)
    return jsonify({'profile_picture_url': decrypted_url}), 200