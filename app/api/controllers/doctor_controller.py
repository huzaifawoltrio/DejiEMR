# /app/api/controllers/doctor_controller.py
from flask import request, jsonify
from sqlalchemy.exc import IntegrityError
from app.extensions import db
from app.models.user_models import User, Role, DoctorProfile
from app.utils.encryption_util import encryptor

def register_doctor():
    """Handles the logic for registering a new doctor."""
    data = request.get_json()
    
    # --- Validate required fields (username is now required) ---
    required_user_fields = ['username', 'email', 'password', 'first_name', 'last_name']
    required_profile_fields = ['medical_license_number', 'qualifications']
    missing_fields = [f for f in required_user_fields + required_profile_fields if f not in data]
    if missing_fields:
        return jsonify({'error': f"Missing required fields: {', '.join(missing_fields)}"}), 400

    # --- Encrypt user data and check for existence ---
    encrypted_email = encryptor.encrypt(data['email'])
    encrypted_username = encryptor.encrypt(data['username'])

    # Check for uniqueness
    users = User.query.all()
    for user in users:
        decrypted_username = encryptor.decrypt(user.username)
        decrypted_email = encryptor.decrypt(user.email)
        if decrypted_username == data['username']:
            return jsonify({'error': 'Username already exists'}), 409
        if decrypted_email == data['email']:
            return jsonify({'error': 'Email already exists'}), 409

    # --- Create the User record ---
    doctor_role = Role.query.filter_by(name='doctor').first()
    if not doctor_role:
        return jsonify({'error': "The 'doctor' role has not been configured in the system."}), 500

    new_user = User(
        username=encrypted_username,
        email=encrypted_email,
        role_id=doctor_role.id
    )
    try:
        new_user.set_password(data['password'])
    except ValueError as e:
        return jsonify({'error': str(e)}), 400

    # --- Create the DoctorProfile record ---
    doctor_profile = DoctorProfile(
        user=new_user,
        first_name=encryptor.encrypt(data['first_name']),
        last_name=encryptor.encrypt(data['last_name']),
        medical_license_number=encryptor.encrypt(data['medical_license_number']),
        qualifications=encryptor.encrypt(data['qualifications']),
        npi_number=encryptor.encrypt(data.get('npi_number')) if data.get('npi_number') else None,
        dea_number=encryptor.encrypt(data.get('dea_number')) if data.get('dea_number') else None,
        profile_picture_url=encryptor.encrypt(data.get('profile_picture_url')) if data.get('profile_picture_url') else None,
        biography=encryptor.encrypt(data.get('biography')) if data.get('biography') else None,
        languages_spoken=encryptor.encrypt(data.get('languages_spoken')) if data.get('languages_spoken') else None,
        department=data.get('department'),
        specialization=data.get('specialization'),
        years_of_experience=data.get('years_of_experience'),
        available_for_telehealth=data.get('available_for_telehealth', False)
    )

    # --- Commit to database ---
    try:
        db.session.add(new_user)
        db.session.add(doctor_profile)
        db.session.commit()
        return jsonify({'message': 'Doctor registered successfully', 'user_id': new_user.id}), 201
    except IntegrityError as e:
        db.session.rollback()
        return jsonify({'error': 'A database integrity error occurred. A unique value (like license number) might already exist.'}), 409
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500

# get_all_doctors function remains the same
def get_all_doctors():
    """Retrieves a list of all doctors with their decrypted profile information."""
    doctor_role = Role.query.filter_by(name='doctor').first()
    if not doctor_role:
        return jsonify({'doctors': []}), 200

    doctors = db.session.query(User, DoctorProfile).join(DoctorProfile).filter(User.role_id == doctor_role.id).all()

    doctor_list = []
    for user, profile in doctors:
        doctor_list.append({
            'user_id': user.id,
            'email': encryptor.decrypt(user.email),
            'first_name': encryptor.decrypt(profile.first_name),
            'last_name': encryptor.decrypt(profile.last_name),
            'department': profile.department,
            'specialization': profile.specialization,
            'medical_license_number': encryptor.decrypt(profile.medical_license_number),
            'qualifications': encryptor.decrypt(profile.qualifications),
            'years_of_experience': profile.years_of_experience,
            'npi_number': encryptor.decrypt(profile.npi_number),
            'dea_number': encryptor.decrypt(profile.dea_number),
            'available_for_telehealth': profile.available_for_telehealth,
            'profile_picture_url': encryptor.decrypt(profile.profile_picture_url),
            'biography': encryptor.decrypt(profile.biography),
            'languages_spoken': encryptor.decrypt(profile.languages_spoken),
            'is_active': user.is_active,
            'last_login': user.last_login.isoformat() if user.last_login else None
        })
        
    return jsonify({'doctors': doctor_list}), 200
